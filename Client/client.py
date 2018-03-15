import pickle
import socket
import threading
import time

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random.random import randrange
from Cryptodome.Util import Padding

from Util.prime_helper import PrimeHelper


# TODO: Make sure to replace prime.dmp with larger prime

class UDPClient(object):
    """
    Connect to Server, send/receive data
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("localhost", 0))

        self.prime_dump = "data/prime.dmp"
        self.helper = PrimeHelper(self.prime_dump)
        self.helper.read()

        self.wait = threading.Event()
        self.conn_accepted = False

        self.cipher = None
        self.key = None

        self.send_message("New Client")

    def set_key(self, key, nonce=None):
        self.cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def int_to_bytes(num):
        return num.to_bytes((num.bit_length() + 7) // 8, "big")

    def dh_key_exchange(self, mode="Request"):
        if mode == "Request":
            timeout = 0
            secret = randrange(1, self.helper.prime)  # Random integer between 1 and prime - 1: to be kept secret

            public = (self.helper.root ** secret) % self.helper.prime  # Public part, shared in the clear

            self.send_message("Request Key Exchange")
            while not self.conn_accepted:
                if timeout > 10:
                    raise TimeoutError("Connection timed out")
                time.sleep(1)

                timeout += 1

            self.send_message(str(self.helper.prime))
            self.send_message(str(self.helper.root))
            self.send_message(str(public))  # Send public information

            response = int(self.receive_single())

            self.wait.set()

            # Calculate and return shared secret
            return SHA3_256.new(self.int_to_bytes((response ** secret) % self.helper.prime))
        elif mode == "Response":
            self.send_message("Key Exchange Accepted")
            prime = int(self.receive_single())
            root = int(self.receive_single())
            response = int(self.receive_single())  # Receive public information

            secret = randrange(1, prime)  # Random integer between 1 and prime - 1: to be kept secret

            public = (root ** secret) % prime  # Public part, shared in the clear

            self.send_message(str(public))  # Send public information

            # Calculate and return shared secret
            return SHA3_256.new(self.int_to_bytes((response ** secret) % self.helper.prime))

    def encrypt(self, key, plaintext: bytes, nonce=None):
        # Setup cipher
        self.set_key(key, nonce)

        # Get randomly generated nonce from cipher if not specified
        if nonce is None:
            nonce = self.cipher.nonce

        ciphertext, tag = self.cipher.encrypt_and_digest(Padding.pad(plaintext, 16))
        return ciphertext, tag, nonce

    def decrypt(self, key, ciphertext: bytes, tag, nonce):
        # Setup cipher
        self.set_key(key, nonce)

        plaintext = Padding.unpad(self.cipher.decrypt(ciphertext), 16)

        # Verify message integrity
        try:
            self.cipher.verify(tag)
        except ValueError:
            print("WARNING: Message Corrupted!")

        return plaintext

    def send_message(self, msg):
        self.sock.sendto(bytes(msg, "utf-8"), (self.host, self.port))

    def send_tuple(self, tup):
        self.sock.sendto(pickle.dumps(tup), (self.host, self.port))

    def send_encrypted_message(self, msg):
        if self.key is not None:
            self.send_tuple(self.encrypt(self.key, bytes(msg, "utf-8")))
        else:
            try:
                self.key = self.dh_key_exchange().digest()
                self.send_tuple(self.encrypt(self.key, bytes(msg, "utf-8")))
            except TimeoutError:
                print(f"Connection timed out, resending message '{msg}'...")
                self.send_encrypted_message(msg)

    def format(self, msg):
        try:
            return str(msg, "utf-8")
        except UnicodeDecodeError:
            return str(self.decrypt(self.key, *(pickle.loads(msg))), "utf-8")

    def receive_single(self):
        return str(self.sock.recv(1024), "utf-8")

    def receive_forever(self, event):
        """
        Prints data received from Server. To be run in a separate
        daemon thread.
        """
        while True:
            received = self.format(self.sock.recv(1024))

            if received == "Request Key Exchange":
                self.key = self.dh_key_exchange(mode="Response").digest()
            elif received == "Key Exchange Accepted":
                self.conn_accepted = True
                event.wait()
            else:
                print(received)

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    with UDPClient(HOST, PORT) as client:
        receive_thread = threading.Thread(target=client.receive_forever, args=(client.wait,))
        receive_thread.daemon = True
        receive_thread.start()

        while True:
            client.send_encrypted_message(input("=> "))
