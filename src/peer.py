import socket

HOST = "127.0.0.1"
PORT = 5000


def start_peer():
    """Start a peer that waits for another peer to connect."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)

        print(f"Peer A is listening on {HOST}:{PORT}")
        print("Waiting for Peer B to connect...")

        connection, address = server.accept()

        with connection:
            print(f"Peer B connected from {address}")

            data = connection.recv(1024)

            if data:
                message = data.decode("utf-8")
                print(f"Message received: {message}")
                connection.sendall(b"Message received successfully!")


if __name__ == "__main__":
    start_peer()