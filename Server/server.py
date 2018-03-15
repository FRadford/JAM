import socketserver
import threading
from typing import Type


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """
    Essentially a socketserver.UDPServer, with the addition of a persistent client list. Dispatches an instance of
    the specified request_handler_class for each request and passes on relevant request information.
    """

    def __init__(self, server_address: tuple, request_handler_class: Type[socketserver.BaseRequestHandler]):
        super(ThreadedUDPServer, self).__init__(server_address, request_handler_class)
        self.client_list = []


class ThreadedUDPHandler(socketserver.BaseRequestHandler):
    """
    Handle Client Connections
    """

    def __init__(self, request: tuple, client_address: str, dispatcher: ThreadedUDPServer):
        if client_address not in dispatcher.client_list:  # Add new clients to the server client list
            dispatcher.client_list.append(client_address)
        super(ThreadedUDPHandler, self).__init__(request, client_address, dispatcher)

    def handle(self):
        """
        Receives data from client, prints data before forwarding to all other clients
        """
        data = self.request[0].strip()
        socket = self.request[1]

        if data != b"New Client":
            print(f"{self.client_address}: {threading.current_thread().getName()} wrote:")
            print(data)

            for client in self.server.client_list:
                if client != self.client_address:
                    socket.sendto(data, client)

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    server = ThreadedUDPServer((HOST, PORT), ThreadedUDPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    print(f"Server loop running in thread: {server_thread.name}")
