'''
Modifications (branch overlay-improvements)
   1. The server is now a BootstrapServer class (start, stop, port 0).
      Why: with module-level globals, the attack tests (Step 7) and the
      simulation (Step 8) could not start it on a free port or stop it.
      'python -m src.bootstrap' still works as before.

   2. 'register' also stores the peer's file port and neighbours.
      Why: peers now look up file ports and links here instead of in
      hardcoded tables.

   3. New 'topology' action that lists every peer.
      Why: 'discover' hides the requester, but computing a full route
      needs every peer, including the sender.

   4. Socket timeout on every request (handle_peer).
      Why: a client that connected and sent nothing kept its handler
      thread waiting forever.

   5. Host, port and limits come from src/config.py.

'''
import json
import socket
import threading

from src import config
from src.peer_directory import PeerDirectory

HOST = config.BOOTSTRAP_BIND
PORT = config.BOOTSTRAP_PORT
MAX_MESSAGE_SIZE = config.MAX_MESSAGE_SIZE


# Bootstrap server for peer registration and discovery.
class BootstrapServer:
    def __init__(self, host=HOST, port=PORT, verbose=True):
        self.host = host
        self.port = port
        self.verbose = verbose

        self.directory = PeerDirectory()
        self.directory_lock = threading.Lock()

        self._server = None
        self._running = threading.Event()

    def log(self, text):
        if self.verbose:
            print(text)

    # Apply one bootstrap request and return the response.
    def process_request(self, request, address=None):
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")

        action = request.get("action")
        peer_id = request.get("peer_id")

        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("Invalid peer ID")

        if action == "register":
            peer_host = request.get("host")
            peer_port = request.get("port")

            with self.directory_lock:
                self.directory.register(
                    peer_id,
                    peer_host,
                    peer_port,
                    request.get("file_port"),
                    request.get("neighbours"),
                )
                peers = self.directory.get_peers(exclude_peer_id=peer_id)

            self.log(f"Registered {peer_id} from {address}")
            return {"status": "ok", "peers": peers}

        if action == "discover":
            with self.directory_lock:
                peers = self.directory.get_peers(exclude_peer_id=peer_id)

            self.log(f"Discovery request from {peer_id}")
            return {"status": "ok", "peers": peers}

        if action == "topology":
            with self.directory_lock:
                peers = self.directory.get_peers()

            return {"status": "ok", "peers": peers}

        return {"status": "error", "message": "Unknown action"}

    # Read one request from a connection and send the reply.
    def handle_peer(self, connection, address):
        with connection:
            connection.settimeout(config.SOCKET_TIMEOUT)

            try:
                with connection.makefile("rb") as stream:
                    data = stream.readline(MAX_MESSAGE_SIZE + 1)

                if (
                    not data
                    or len(data) > MAX_MESSAGE_SIZE
                    or not data.endswith(b"\n")
                ):
                    self.log(f"Rejected invalid request from {address}")
                    return

                request = json.loads(data.decode("utf-8"))
                response = self.process_request(request, address)

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
                self.log(f"Connection error from {address}")
                return

            try:
                connection.sendall(
                    json.dumps(response).encode("utf-8") + b"\n"
                )
            except OSError:
                self.log(f"Could not send response to {address}")

    # Open the listening socket (port 0 picks a free port).
    def bind(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen()

        # A short accept timeout lets the loop notice stop() quickly.
        self._server.settimeout(0.5)

        self.port = self._server.getsockname()[1]
        self._running.set()

        self.log(f"Bootstrap server listening on {self.host}:{self.port}")

    # Accept connections until stop() is called.
    def serve_forever(self):
        if self._server is None:
            self.bind()

        while self._running.is_set():
            try:
                connection, address = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            thread = threading.Thread(
                target=self.handle_peer,
                args=(connection, address),
                daemon=True,
            )
            thread.start()

    # Run the server in a background thread.
    def start(self):
        self.bind()
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    # Stop accepting connections.
    def stop(self):
        self._running.clear()

        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass


# Command-line entry point: run the server on the configured port.
def start_bootstrap():
    BootstrapServer().serve_forever()


if __name__ == "__main__":
    start_bootstrap()
