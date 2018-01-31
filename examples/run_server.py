import socketserver

from server.Server import TCPHandler

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        server.serve_forever()
