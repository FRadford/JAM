from Server.server import ThreadedUDPServer, ThreadedUDPHandler


def create_db(db_path):
    """
    Creates a database file under the specified path
    """
    server = ThreadedUDPServer(("localhost", 9999), ThreadedUDPHandler, db_path)
    server.init_db()

    print("Database Initialized")


if __name__ == "__main__":
    create_db("data/users.db")
