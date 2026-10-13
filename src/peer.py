import socket

from src.message import (
    canonical_message,
    encode_secure_message,
    decode_secure_message,
)
from src.security import calculate_hmac, verify_hmac

HOST = "127.0.0.1"
PORT = 5000

# Demonstration key only; both peers must use the same key.
SECRET_KEY = b"demo-shared-key-change-later"


def start_peer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)

        print(f"Peer A listening on {HOST}:{PORT}")
        print("Waiting for Peer B...")

        connection, address = server.accept()

        with connection:
            print(f"Connected to {address}")

            with connection.makefile("rb") as stream:
                data = stream.readline(4097)

            if not data or len(data) > 4096 or not data.endswith(b"\n"):
                print("Rejected: invalid or oversized message.")
                return

            try:
                sender, content, tag, original_bytes = (
                    decode_secure_message(data[:-1])
                )
            except (ValueError, UnicodeDecodeError):
                print("Rejected: malformed message.")
                return

            if not verify_hmac(original_bytes, SECRET_KEY, tag):
                print("Rejected: HMAC verification failed.")
                return

            print(f"Authenticated message from {sender}: {content}")

            reply = "Message authenticated successfully!"
            reply_bytes = canonical_message("Peer A", reply)
            reply_tag = calculate_hmac(reply_bytes, SECRET_KEY)

            connection.sendall(
                encode_secure_message("Peer A", reply, reply_tag)
            )


if __name__ == "__main__":
    start_peer()