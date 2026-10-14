
import json
import socket
import threading

from src.peer_directory import PeerDirectory

HOST = "127.0.0.1"
PORT = 6000
MAX_MESSAGE_SIZE = 4096

directory = PeerDirectory()
directory_lock = threading.Lock()


def handle_peer(connection, address):
    with connection:
        try:
            with connection.makefile("rb") as stream:
                data = stream.readline(MAX_MESSAGE_SIZE + 1)

            if (
                not data
                or len(data) > MAX_MESSAGE_SIZE
                or not data.endswith(b"\n")
            ):
                print(f"Rejected invalid request from {address}")
                return

            request = json.loads(data.decode("utf-8"))

            if not isinstance(request, dict):
                raise ValueError("Request must be a JSON object")

            action = request.get("action")
            peer_id = request.get("peer_id")

            if not isinstance(peer_id, str) or not peer_id.strip():
                raise ValueError("Invalid peer ID")

            if action == "register":
                peer_host = request.get("host")
                peer_port = request.get("port")

                with directory_lock:
                    directory.register(peer_id, peer_host, peer_port)
                    peers = directory.get_peers(
                        exclude_peer_id=peer_id
                    )

                response = {
                    "status": "ok",
                    "peers": peers,
                }

                print(f"Registered {peer_id} from {address}")

            elif action == "discover":
                with directory_lock:
                    peers = directory.get_peers(
                        exclude_peer_id=peer_id
                    )

                response = {
                    "status": "ok",
                    "peers": peers,
                }

                print(f"Discovery request from {peer_id}")

            else:
                response = {
                    "status": "error",
                    "message": "Unknown action",
                }

        except (
            ValueError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            response = {
                "status": "error",
                "message": "Invalid request",
            }

        except (ConnectionError, OSError):
            print(f"Connection error from {address}")
            return

        try:
            connection.sendall(
                json.dumps(response).encode("utf-8") + b"\n"
            )
        except OSError:
            print(f"Could not send response to {address}")


def start_bootstrap():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()

        print(f"Bootstrap server listening on {HOST}:{PORT}")

        while True:
            connection, address = server.accept()

            thread = threading.Thread(
                target=handle_peer,
                args=(connection, address),
                daemon=True,
            )
            thread.start()


if __name__ == "__main__":
    start_bootstrap()
