import socket
import os

from src.message import (
    canonical_message,
    encode_secure_message,
    decode_secure_message,
)
from src.security import calculate_hmac, verify_hmac

HOST = os.getenv("P2P_PEER_HOST", "127.0.0.1")
PORT = 5000

# Must match the demonstration key in peer.py.
SECRET_KEY = b"demo-shared-key-change-later"


def connect_to_peer():
    message = input("Enter a message to send to Peer A: ")

    message_bytes = canonical_message("Peer B", message)
    tag = calculate_hmac(message_bytes, SECRET_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        client.sendall(
            encode_secure_message("Peer B", message, tag)
        )

        with client.makefile("rb") as stream:
            data = stream.readline(4097)

        if not data or len(data) > 4096 or not data.endswith(b"\n"):
            print("Invalid or oversized reply.")
            return

        try:
            sender, content, received_tag, original_bytes = (
                decode_secure_message(data[:-1])
            )
        except (ValueError, UnicodeDecodeError):
            print("Rejected: malformed reply.")
            return

        if not verify_hmac(original_bytes, SECRET_KEY, received_tag):
            print("Rejected: reply HMAC verification failed.")
            return

        print(f"Verified reply from {sender}: {content}")


if __name__ == "__main__":
    connect_to_peer()