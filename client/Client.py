import socket


class UDPClient(object):
    """
    Connect to server, send/receive data
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("localhost", 0))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_msg(self, msg):
        self.sock.sendto(bytes(msg, "utf-8"), (self.host, self.port))

    def receive_single(self):
        return str(self.sock.recv(1024), "utf-8")

    def receive_forever(self):
        """
        Yields data received from server. To be run in separate daemon thread

        :return: Iterator[str]
        """
        while True:
            print(str(self.sock.recv(1024), "utf-8"))

    def close(self):
        self.sock.close()
