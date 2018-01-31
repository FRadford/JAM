import socket


class Client(object):
    """
    Connect to server, send/receive data
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sock.close()

    def get_connection(self):
        try:
            self.sock.connect((self.host, self.port))
        except Exception as e:
            print(e)

    def send_msg(self, msg):
        self.get_connection()
        self.sock.sendall(bytes(msg, "utf-8"))

    def recv_msg(self):
        return str(self.sock.recv(1024), "utf-8")
