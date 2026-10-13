import socket

HOST = "127.0.0.1"
PORT = 5000


def connect_to_peer():
    """Connect to Peer A and exchange a message."""

    message = input("Enter a message to send to Peer A: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        client.sendall(message.encode("utf-8"))

        response = client.recv(1024)
        print("Reply from Peer A:", response.decode("utf-8"))


if __name__ == "__main__":
    connect_to_peer()