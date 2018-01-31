import socketserver


class TCPHandler(socketserver.BaseRequestHandler):
    """
    Handle client Connections
    """

    def __init__(self, request, client_address, server):
        self.data = ""
        super(TCPHandler, self).__init__(request, client_address, server)

    def handle(self):
        self.data = self.request.recv(1024).strip()
        print(f"{self.client_address[0]} wrote:")
        print(self.data)

        self.request.sendall(self.data.upper())
