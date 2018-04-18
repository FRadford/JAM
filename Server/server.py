import socketserver
import sqlite3
import threading
from typing import Type

import yaml
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random.random import randrange, getrandbits

from MessageTypes.message import EncryptedMessage
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
            dispatcher.client_list[client_address] = ClientInfo(client_address, self)

        self.cipher = None

        super(ThreadedUDPHandler, self).__init__(request, client_address, dispatcher)

    @staticmethod
    def decode_yaml(msg: bytes):
        try:
            return yaml.load(msg)
        except yaml.YAMLError:
            return msg

    @staticmethod
    def int_to_bytes(num: int) -> bytes:
        """
        Helper function to convert integer to bytes representation
        """
        return num.to_bytes((num.bit_length() + 7) // 8, "big")

    @staticmethod
    def format(msg: bytes or str) -> str:
        """
        Decrypts and decodes encrypted messages, decodes non-encrypted messages
        """
        try:
            return str(msg, "utf-8")
        except (UnicodeDecodeError, TypeError):
            return msg

    def handle(self):
        """
        Receives data from client, prints data before forwarding to all other clients
        """
        data = self.decode_yaml(self.request[0].strip())
        client = self.server.client_list[self.client_address]

        if type(data) is tuple:
            if data[0] == "Request Key Exchange":
                client.dh_key_exchange(*[int(x) for x in data[1:]])
            elif type(data[0]) is EncryptedMessage:
                if data[0].decrypt() == "register":
                    client.register(data[1].decrypt(), data[2].decrypt())
                elif data[0].decrypt() == "login":
                    client.login(data[1].decrypt(), data[2].decrypt())

    def send_message(self, msg: str):
        """
        Sends encoded message to client
        """
        self.request[1].sendto(bytes(msg, "utf-8"), self.client_address)

    def send_encrypted_message(self, msg: str):
        """
        Encrypts and sends message if key is established or begins key exchange if no key exists
        """
        self.send_message(yaml.dump(EncryptedMessage(self.server.client_list[self.client_address].key, msg)))


class ClientInfo(object):
    """
    Basic class to hold client information (username, ip address, etc)
    """

    def __init__(self, client_address, handler: ThreadedUDPHandler, username=None, key=None):
        self.ip_address = client_address
        self.username = username
        self.key = key

        # read prime for use in key exchange
        self.prime_dump = "data/prime.bin"
        self.helper = PrimeHelper(self.prime_dump)
        self.helper.read()

        self.handler = handler

    def dh_key_exchange(self, prime, root, received_public):
        secret = randrange(1, prime)  # Random integer between 1 and prime - 1: to be kept secret

        public = (root ** secret) % prime  # Public part, shared in the clear

        self.handler.send_message("Key Exchange Accepted")
        self.handler.send_message(str(public))  # Send public information

        # Calculate and return shared secret
        self.key = SHA3_256.new(self.handler.int_to_bytes((received_public ** secret) % self.helper.prime)).digest()

    def register(self, username, password):
        cursor = self.handler.server.database.cursor()

        salt = str(getrandbits(64))
        statement = "INSERT INTO users(username, password, salt) VALUES (?,?,?)"

        try:
            cursor.execute(statement, (username, SHA3_256.new(bytes(password + salt, "utf-8")).hexdigest(), salt))
            self.handler.send_encrypted_message("Successfully Registered.")

            self.username = username
        except sqlite3.IntegrityError:
            self.handler.send_encrypted_message("Username Already Registered.")

        self.handler.server.database.commit()
        self.handler.server.database.close()
        self.handler.server.database = None

    def login(self, username, password):
        cursor = self.handler.server.database.cursor()
        username = (username,)

        saved_user, saved_pass, salt = cursor.execute("SELECT username, password, salt FROM users WHERE username=?",
                                                      username).fetchone()

        if SHA3_256.new(bytes(password + salt, "utf-8")).hexdigest() == saved_pass:
            self.handler.send_encrypted_message("Login Successful.")

            self.username = username
        else:
            self.handler.send_encrypted_message("Login Failed.")

        self.handler.server.database.close()
        self.handler.server.database = None


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    server = ThreadedUDPServer((HOST, PORT), ThreadedUDPHandler, "data/users.db")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    print(f"Server loop running in thread: {server_thread.name}")
