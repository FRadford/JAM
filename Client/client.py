import socket
import threading

import yaml
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random.random import randrange

from MessageTypes.message import EncryptedMessage
from Util.prime_helper import PrimeHelper


# TODO: Make sure to replace prime.bin with larger prime


class UDPClient(object):
    """
    Connect to Server, send/receive data
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        # setup socket to send and receive data
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("localhost", 0))  # bind socket to local host and any available port

        # read prime for use in key exchange
        self.prime_dump = "data/prime.bin"
        self.helper = PrimeHelper(self.prime_dump)
        self.helper.read()

        # setup event to pause receiving thread during key exchange
        self.wait = threading.Event()
        self.exchange = False

        self.key = None

    # functions to allow with ... as ... paradigm
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def int_to_bytes(num: int) -> bytes:
        """
        Helper function to convert integer to bytes representation
        """
        return num.to_bytes((num.bit_length() + 7) // 8, "big")

    @staticmethod
    def hash_password(password):
        return SHA3_256.new(password)

    @staticmethod
    def format(msg: bytes) -> str:
        """
        Decrypts and decodes encrypted messages, decodes non-encrypted messages
        """
        try:
            return str(msg, "utf-8")
        except (UnicodeDecodeError, TypeError):
            return yaml.load(msg).decrypt()

    @staticmethod
    def prompt():
        print("Enter Username")
        username = input("=> ")

        print("Enter Password")
        password = input("=> ")

        return username, password

    def dh_key_exchange(self, originator: bool = True) -> SHA3_256:
        """
        Facilitates both sides of a basic Diffie-Hellman key exchange and generates a shared secret, the hash of this
        secret is returned to be used as a key for the cipher
        """

        # TODO: Fix key exchange. Probably by keeping a key for every other user.
        if originator:
            secret = randrange(1, self.helper.prime)  # Random integer between 1 and prime - 1: to be kept secret

            public = (self.helper.root ** secret) % self.helper.prime  # Public part, shared in the clear

            # Send public information
            self.exchange = True
            self.send_many("Request Key Exchange", str(self.helper.prime), str(self.helper.root), str(public))

            response = int(self.receive_single())

            self.wait.set()
            self.exchange = False

            # Calculate and return shared secret
            return SHA3_256.new(self.int_to_bytes((response ** secret) % self.helper.prime))
        else:
            self.send_message("Key Exchange Accepted")
            prime = int(self.receive_single())
            root = int(self.receive_single())
            response = int(self.receive_single())  # Receive public information

            secret = randrange(1, prime)  # Random integer between 1 and prime - 1: to be kept secret

            public = (root ** secret) % prime  # Public part, shared in the clear

            self.send_message(str(public))  # Send public information

            # Calculate and return shared secret
            return SHA3_256.new(self.int_to_bytes((response ** secret) % self.helper.prime))

    def send_message(self, msg: str):
        """
        Sends encoded message to connected server
        """
        self.sock.sendto(bytes(msg, "utf-8"), (self.host, self.port))

    def send_many(self, *args):
        """
        Encodes tuple then sends to connected server
        """
        self.sock.sendto(bytes(yaml.dump(args), "utf-8"), (self.host, self.port))

    def send_encrypted_message(self, msg: str):
        """
        Encrypts and sends message if key is established or begins key exchange if no key exists
        """
        if not self.key:
            self.key = self.dh_key_exchange().digest()

        if msg.startswith("~"):
            if msg == "~register" or msg == "~login":
                self.login(msg[1:])
        else:
            self.send_message(yaml.dump(EncryptedMessage(self.key, msg)))

    def login(self, msg):
        username, password = self.prompt()
        hashed = SHA3_256.new(bytes(password, "utf-8")).hexdigest()

        self.send_many(EncryptedMessage(self.key, msg),
                       EncryptedMessage(self.key, username),
                       EncryptedMessage(self.key, hashed))

    def receive_single(self) -> str:
        """
        Blocks until a message is received on the socket, returns decoded text
        """
        return self.format(self.sock.recv(1024))

    def receive_forever(self, event):
        """
        Prints data received from Server. To be run in a separate
        daemon thread.
        """
        while True:
            received = self.format(self.sock.recv(1024))

            if self.exchange:
                event.wait()
            elif received == "Request Key Exchange":
                self.key = self.dh_key_exchange(originator=False).digest()
            elif received == "Key Exchange Accepted":
                pass
            else:
                print(self.format(received))

    def close(self):
        """
        Shuts down client gracefully, usually called from the __exit__ method
        """
        self.sock.close()


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    with UDPClient(HOST, PORT) as client:
        receive_thread = threading.Thread(target=client.receive_forever, args=(client.wait,))
        receive_thread.daemon = True
        receive_thread.start()

        while True:
            client.send_encrypted_message(input("=> "))
