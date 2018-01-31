import sys

from client.Client import Client

HOST, PORT = "localhost", 9999
data = " ".join(sys.argv[1:])

with Client(HOST, PORT) as client:
    client.send_msg(data)
    print(client.recv_msg())
