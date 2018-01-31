import threading

from client.Client import UDPClient

HOST, PORT = "localhost", 9999

with UDPClient(HOST, PORT) as client:
    receive_thread = threading.Thread(target=client.receive_forever)
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        client.send_msg(input("=> "))
