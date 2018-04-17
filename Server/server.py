import pickle
import socketserver
import sqlite3
import threading
from typing import Type

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random.random import randrange, getrandbits
from Cryptodome.Util import Padding

from Util.prime_helper import PrimeHelper


# TODO: Add client class to simplify client list


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """
    Essentially a socketserver.UDPServer, with the addition of a persistent client list. Dispatches an instance of
    the specified request_handler_class for each request and passes on relevant request information.
    """

    def __init__(self, server_address: tuple, request_handler_class: Type[socketserver.BaseRequestHandler],
                 db_path: str):
        super(ThreadedUDPServer, self).__init__(server_address, request_handler_class)

        self.db_path = db_path

        self.client_list = {}
        self._database = None

    def connect_db(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    @property
    def database(self):
        if not self._database:
            self._database = self.connect_db()
        return self._database

    @database.setter
    def database(self, value):
        self._database = value

    def close_db(self, error=None):
        if self.database:
            self.database.close()

        print(error if error else "Database connection successfully closed")

    def init_db(self):
        with open("data/schema.sql", mode="r") as f:
            self.database.cursor().executescript(f.read())
        self.database.commit()


class ThreadedUDPHandler(socketserver.BaseRequestHandler):
    """
    Handle Client Connections
    """

    def __init__(self, request: tuple, client_address: str, dispatcher: ThreadedUDPServer):
        if client_address not in dispatcher.client_list:  # Add new clients to the server client list
            dispatcher.client_list[client_address] = False

        # read prime for use in key exchange
        self.prime_dump = "data/prime.bin"
        self.helper = PrimeHelper(self.prime_dump)
        self.helper.read()

        self.cipher = None

        super(ThreadedUDPHandler, self).__init__(request, client_address, dispatcher)

    def handle(self):
        """
        Receives data from client, prints data before forwarding to all other clients
        """
        data = self.request[0].strip()
        socket = self.request[1]

        if not self.server.client_list[self.client_address]:
            self.server.client_list[self.client_address] = {"Key Exchange": False, "prime": None, "root": None,
                                                            "response": None, "key": None, "Register": False,
                                                            "username": None, "password": None, "Login": False}

        if data == b"Request Key Exchange":
            self.dh_key_exchange()

        elif self.server.client_list[self.client_address]["Key Exchange"]:
            exchange_data = pickle.loads(data)
            self.server.client_list[self.client_address]["prime"], \
            self.server.client_list[self.client_address]["root"], \
            self.server.client_list[self.client_address]["response"] = [int(x) for x in exchange_data]

            secret = self.dh_key_exchange()
            self.server.client_list[self.client_address]["key"] = secret.digest() if secret else None

        elif data == b"Register":
            self.server.client_list[self.client_address]["Register"] = True

        elif self.server.client_list[self.client_address]["Register"]:
            if not self.server.client_list[self.client_address]["username"]:
                self.server.client_list[self.client_address]["username"] = self.format(data)
            elif not self.server.client_list[self.client_address]["password"]:
                self.server.client_list[self.client_address]["password"] = self.format(data)
                self.register(self.server.client_list[self.client_address]["username"],
                              self.server.client_list[self.client_address]["password"])

        elif data == b"Login":
            self.server.client_list[self.client_address]["Login"] = True

        elif self.server.client_list[self.client_address]["Login"]:
            if not self.server.client_list[self.client_address]["username"]:
                self.server.client_list[self.client_address]["username"] = self.format(data)
            elif not self.server.client_list[self.client_address]["password"]:
                self.server.client_list[self.client_address]["password"] = self.format(data)
                self.login(self.server.client_list[self.client_address]["username"],
                           self.server.client_list[self.client_address]["password"])




                # if data != b"New Client":
                #     print(f"{self.client_address}: {threading.current_thread().getName()} wrote:")
                #     print(data)
                #
                #     if data == b"Key Exchange Accepted":
                #         for client, flag in self.server.client_list.items():
                #             if flag:
                #                 socket.sendto(data, client)
                #                 self.server.client_list[client] = False
                #     else:
                #         if data == b"Request Key Exchange":
                #             self.server.client_list[self.client_address] = True
                #
                #         for client in self.server.client_list:
                #             if client != self.client_address:
                #                 socket.sendto(data, client)

    def send_message(self, msg: str):
        """
        Sends encoded message to client
        """
        self.request[1].sendto(bytes(msg, "utf-8"), self.client_address)

    def send_tuple(self, tup: tuple):
        """
        Pickles tuple then sends to host address specified on the instance
        """
        self.request[1].sendto(pickle.dumps(tup), self.client_address)

    def send_encrypted_message(self, msg: str):
        """
        Encrypts and sends message if key is established or begins key exchange if no key exists
        """
        self.send_tuple(self.encrypt(self.server.client_list[self.client_address]["key"], bytes(msg, "utf-8")))

    def format(self, msg: bytes) -> str:
        """
        Decrypts and decodes encrypted messages, decodes non-encrypted messages
        """
        try:
            return str(msg, "utf-8")
        except UnicodeDecodeError:
            return str(self.decrypt(self.server.client_list[self.client_address]["key"], *(pickle.loads(msg))), "utf-8")

    def encrypt(self, key: bytes, plaintext: bytes, nonce: bytes = None) -> (bytes, bytes, bytes):
        """
        Encrypts input text with input key and nonce using cipher specified on the instance and generates a tag that
        can be used to verify message integrity

        Returns a tuple with the encrypted text, hash for checking integrity, and nonce
        """
        # Setup cipher
        self.set_key(key, nonce)

        # Get randomly generated nonce from cipher if not specified
        if nonce is None:
            nonce = self.cipher.nonce

        ciphertext, tag = self.cipher.encrypt_and_digest(Padding.pad(plaintext, 16))
        return ciphertext, tag, nonce

    def decrypt(self, key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
        """
        Decrypts encrypted text with cipher specified on the instance and checks tag to verify message integrity
        """
        # Setup cipher
        self.set_key(key, nonce)

        plaintext = Padding.unpad(self.cipher.decrypt(ciphertext), 16)

        # Verify message integrity
        try:
            self.cipher.verify(tag)
        except ValueError:
            print("WARNING: Message Corrupted!")

        return plaintext

    def set_key(self, key: bytes, nonce: bytes = None):
        """
        Helper function to setup cipher and store on instance

        If nonce is not specified it will be generated by the cipher
        """
        self.cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    @staticmethod
    def int_to_bytes(num: int) -> bytes:
        """
        Helper function to convert integer to bytes representation
        """
        return num.to_bytes((num.bit_length() + 7) // 8, "big")

    def dh_key_exchange(self) -> SHA3_256:
        """
        Facilitates the receiving end of a basic Diffie-Hellman key exchange and generates a shared secret,
        the hash of this secret is returned to be used as a key for the cipher
        """

        connection = self.server.client_list[self.client_address]

        if not connection["Key Exchange"]:
            self.send_message("Key Exchange Accepted")
            connection["Key Exchange"] = True
        elif connection["prime"] and connection["root"] and connection["response"]:
            secret = randrange(1, connection["prime"])  # Random integer between 1 and prime - 1: to be kept secret

            public = (connection["root"] ** secret) % connection["prime"]  # Public part, shared in the clear

            connection["Key Exchange"] = False
            self.send_message(str(public))  # Send public information

            # Calculate and return shared secret
            return SHA3_256.new(self.int_to_bytes((connection["response"] ** secret) % self.helper.prime))
        return None

    def register(self, username, password):
        cursor = self.server.database.cursor()

        salt = str(getrandbits(64))
        statement = "INSERT INTO users(username, password, salt) VALUES (?,?,?)"

        try:
            cursor.execute(statement, (username, SHA3_256.new(bytes(password + salt, "utf-8")).hexdigest(), salt))
            self.send_encrypted_message("Successfully Registered.")
        except sqlite3.IntegrityError:
            self.send_encrypted_message("Username Already Registered.")

        self.server.client_list[self.client_address]["Register"], \
        self.server.client_list[self.client_address]["username"], \
        self.server.client_list[self.client_address]["password"] = False, None, None

        self.server.database.commit()
        self.server.database.close()
        self.server.database = None

    def login(self, username, password):
        cursor = self.server.database.cursor()
        username = (username,)

        saved_user, saved_pass, salt = cursor.execute("SELECT username, password, salt FROM users WHERE username=?",
                                                      username).fetchone()

        if SHA3_256.new(bytes(password + salt, "utf-8")).hexdigest() == saved_pass:
            self.send_encrypted_message("Login Successful.")
        else:
            self.send_encrypted_message("Login Failed.")

        self.server.client_list[self.client_address]["Login"], \
        self.server.client_list[self.client_address]["username"], \
        self.server.client_list[self.client_address]["password"] = False, None, None

        self.server.database.close()
        self.server.database = None


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    server = ThreadedUDPServer((HOST, PORT), ThreadedUDPHandler, "data/users.db")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    print(f"Server loop running in thread: {server_thread.name}")
