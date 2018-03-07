import socketserver
import threading


class ThreadedUDPHandler(socketserver.BaseRequestHandler):
    """
    Handle Client Connections
    """

    def __init__(self, request, client_address, server):
        if client_address not in server.client_list:
            server.client_list.append(client_address)
        super(ThreadedUDPHandler, self).__init__(request, client_address, server)

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]

        if data != b"New Client":
            print(f"{self.client_address}: {threading.current_thread().getName()} wrote:")
            print(data)

            for client in self.server.client_list:
                if client != self.client_address:
                    socket.sendto(data, client)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super(ThreadedUDPServer, self).__init__(server_address, RequestHandlerClass)
        self.client_list = []


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    server = ThreadedUDPServer((HOST, PORT), ThreadedUDPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    print(f"Server loop running in thread: {server_thread.name}")
