# --- Modifications (branch overlay-improvements) ---
#   1. Hosts, ports and the key come from src/config.py.
#      Why: the file was fixed to 127.0.0.1; now the routed demo and
#      file sharing can run across machines (Windows <-> Kali).
#
#   2. A peer is now a RoutedPeer class. The original functions became
#      methods with their logic and comments kept (register_peer,
#      discover_peers, receive_routed_message, forward_routed_message,
#      handle_file_request, start_peer).
#      Why: global variables allowed only Peer A, B or C. A class lets
#      many peers run, also inside one process for the attack tests and
#      the simulation.
#
#   3. Peer addresses and file ports come from the bootstrap server
#      (get_topology) instead of PEER_ADDRESSES / FILE_TRANSFER_PORTS.
#      Why: discovery is really used, and any number of peers can join.
#
#   4. In forward_routed_message() the routing-table check became an
#      overlay-link check (_has_link).
#      Why: routes may now avoid a peer (quarantine), so a hop checks
#      that the next hop is a real neighbour instead of the usual one.
#      A route that jumps over a missing link is still refused.
#
#   5. Each connection is handled in its own thread with a socket
#      timeout (_start_accept_loop).
#      Why: the old loop handled one connection at a time, so one silent
#      or flooding client froze the whole peer. The flooding tests in
#      Step 7 need the peer to keep working.
#
#   6. send_routed_message() computes the route when none is given,
#      can avoid peers ('excluded' / --avoid), and returns RTT and hops.
#      Why: needed for quarantine (Step 6) and evaluation (Step 9).
#
#   7. Acknowledgement reading and checking moved into
#      read_acknowledgement() and verify_acknowledgement().
#      Why: the same code appeared twice; Step 3 (replay protection)
#      can now extend it in one place.
#
#   8. Command line uses argparse. The original commands (server, send,
#      request-file) work the same; new options: --port, --neighbours,
#      --from, --to, --message, --route, --avoid and 'topology'.
#      Why: to start extra peers and to show the overlay in the demo.
#
#   9. Peer A, B and C keep their original ports and A -> B -> C links
#      by default (config.DEFAULT_NEIGHBOURS).
#      Why: the original demo commands give the same output as before.
#
#   10. (branch replay-protection) Every routed message carries signed
#       freshness fields (msg_id, nonce, timestamp); each peer checks
#       them with its ReplayGuard in receive_routed_message().
#       Why: a captured message could otherwise be sent again later and
#       would still pass the HMAC check.
#
#   11. (branch replay-protection) The ACK repeats the msg_id of its
#       message with its own nonce, and verify_acknowledgement() checks
#       the msg_id and the replay guard.
#       Why: an old 'ok' ACK must not confirm a new message.
#
#   12. (branch replay-protection) File transfers received by a peer are
#       checked with the same replay guard.
#       Why: a captured file transfer could otherwise be replayed.
# ----------------------------------------------------

import argparse
import json
import os
import socket
import threading
import time

from src import config
from src.message import (
    canonical_routed_message,
    encode_secure_routed_message,
    decode_secure_routed_message,
    canonical_acknowledgement,
    encode_secure_acknowledgement,
    decode_secure_acknowledgement,
)

from src.security import calculate_hmac, verify_hmac
from src.replay import ReplayGuard, ReplayError, new_freshness
from src.routing import build_graph, build_routing_table, shortest_path
from src.filesharing import receive_file, send_file

# Peer network configuration
BOOTSTRAP_ADDRESS = (config.BOOTSTRAP_HOST, config.BOOTSTRAP_PORT)

MAX_MESSAGE_SIZE = config.MAX_MESSAGE_SIZE

# Demonstration key: all peers use the same key.
SECRET_KEY = config.SECRET_KEY


# Send one JSON request to the bootstrap server.
def bootstrap_request(request, bootstrap_address=BOOTSTRAP_ADDRESS):
    with socket.create_connection(
        bootstrap_address,
        timeout=config.SOCKET_TIMEOUT
    ) as connection:

        connection.sendall(
            json.dumps(request).encode("utf-8") + b"\n"
        )

        with connection.makefile("rb") as stream:
            data = stream.readline(MAX_MESSAGE_SIZE + 1)

    if (
        not data
        or len(data) > MAX_MESSAGE_SIZE
        or not data.endswith(b"\n")
    ):
        raise RuntimeError("Invalid bootstrap response")

    response = json.loads(data.decode("utf-8"))

    if not isinstance(response, dict):
        raise RuntimeError("Bootstrap response must be an object")

    if response.get("status") != "ok":
        raise RuntimeError(
            response.get("message", "Bootstrap request failed")
        )

    return response


# Return every peer registered with the bootstrap server.
def get_topology(bootstrap_address=BOOTSTRAP_ADDRESS):
    response = bootstrap_request(
        {"action": "topology", "peer_id": "client"},
        bootstrap_address,
    )

    peers = response.get("peers", [])

    if not isinstance(peers, list):
        raise RuntimeError("Invalid peer list")

    return peers


# Find one peer record in a peer list.
def find_peer(peers, peer_id):
    for peer in peers:
        if peer.get("peer_id") == peer_id:
            return peer

    return None


# Read one acknowledgement line from a socket stream.
def read_acknowledgement(stream):
    data = stream.readline(MAX_MESSAGE_SIZE + 1)

    if (
        not data
        or len(data) > MAX_MESSAGE_SIZE
        or not data.endswith(b"\n")
    ):
        raise ValueError("Invalid delivery acknowledgement")

    return data


# Verify an acknowledgement and check that it matches the message.
# The ACK must repeat the msg_id of the message it confirms and must
# pass the replay guard (fresh timestamp, nonce not seen before).
def verify_acknowledgement(data, sender, destination, msg_id, replay_guard):
    # Decode the authenticated acknowledgement.
    (
        status,
        ack_sender,
        ack_destination,
        ack_tag,
        ack_original_bytes,
        ack_freshness,
    ) = decode_secure_acknowledgement(data[:-1], with_freshness=True)

    # Verify the acknowledgement's HMAC.
    if not verify_hmac(
        ack_original_bytes,
        SECRET_KEY,
        ack_tag,
    ):
        raise ValueError("Acknowledgement HMAC verification failed")

    # Confirm that the acknowledgement matches the original message.
    if (
        status != "ok"
        or ack_sender != sender
        or ack_destination != destination
    ):
        raise ValueError(
            "Acknowledgement does not match routed message"
        )

    # Confirm the ACK belongs to this exact message, not an older one.
    if ack_freshness["msg_id"] != msg_id:
        raise ReplayError("Acknowledgement is for a different message")

    # Reject a replayed or stale acknowledgement.
    replay_guard.check(ack_freshness)

    return status, ack_sender, ack_destination


# A peer that forwards authenticated messages and shares files.
class RoutedPeer:
    # Set up the peer; Peer A/B/C get their original ports and links.
    def __init__(
        self,
        peer_id,
        port=None,
        file_port=None,
        neighbours=None,
        bind_host=config.BIND_HOST,
        advertised_host=config.ADVERTISED_HOST,
        bootstrap_address=BOOTSTRAP_ADDRESS,
        socket_timeout=config.SOCKET_TIMEOUT,
        shared_folder="shared_files",
        received_folder=None,
        verbose=True,
    ):
        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("Unknown peer ID")

        # Peer A, B and C keep their original ports (5000-5002).
        if port is None:
            if peer_id not in config.DEFAULT_PEER_PORTS:
                raise ValueError(f"Please give a port for {peer_id}")
            port = config.DEFAULT_PEER_PORTS[peer_id]

        # Separate ports for file transfers
        if file_port is None:
            file_port = port + config.FILE_PORT_OFFSET if port else 0

        if neighbours is None:
            neighbours = config.DEFAULT_NEIGHBOURS.get(peer_id, [])

        self.peer_id = peer_id
        self.port = port
        self.file_port = file_port
        self.neighbours = list(neighbours)
        self.bind_host = bind_host
        self.advertised_host = advertised_host
        self.bootstrap_address = bootstrap_address
        self.socket_timeout = socket_timeout
        self.shared_folder = shared_folder
        self.received_folder = received_folder or os.path.join(
            "received_files",
            peer_id.replace(" ", "_"),
        )
        self.verbose = verbose

        # Latest view of the overlay, refreshed from the bootstrap server.
        self._lock = threading.Lock()
        self.peers = []
        self.graph = {}

        # Remembers recent nonces so replayed messages are rejected.
        self.replay_guard = ReplayGuard()

        self._running = threading.Event()
        self._servers = []

    def log(self, text):
        if self.verbose:
            print(text)

    # ------------------------------------------------------------
    # Bootstrap and overlay view
    # ------------------------------------------------------------

    # Register this peer with the bootstrap server.
    def register_peer(self):
        response = bootstrap_request(
            {
                "action": "register",
                "peer_id": self.peer_id,
                "host": self.advertised_host,
                "port": self.port,
                "file_port": self.file_port,
                "neighbours": self.neighbours,
            },
            self.bootstrap_address,
        )

        self.log(
            f"{self.peer_id} registered at "
            f"{self.advertised_host}:{self.port}"
        )

        return response

    # Discover other peers through the bootstrap server.
    def discover_peers(self):
        response = bootstrap_request(
            {"action": "discover", "peer_id": self.peer_id},
            self.bootstrap_address,
        )

        peers = response.get("peers", [])

        if not isinstance(peers, list):
            raise RuntimeError("Invalid peer list")

        return peers

    # Download the peer list and rebuild the overlay graph.
    def refresh_view(self):
        peers = get_topology(self.bootstrap_address)

        with self._lock:
            self.peers = peers
            self.graph = build_graph(peers)

    # Return this peer's next-hop routing table.
    def routing_table(self):
        self.refresh_view()

        with self._lock:
            return build_routing_table(self.graph, self.peer_id)

    # Find a peer's address, refreshing the view if it is unknown.
    def _peer_record(self, peer_id):
        with self._lock:
            peer = find_peer(self.peers, peer_id)

        if peer is None:
            self.refresh_view()

            with self._lock:
                peer = find_peer(self.peers, peer_id)

        return peer

    # Check whether this peer and peer_id are overlay neighbours.
    def _has_link(self, peer_id):
        with self._lock:
            return peer_id in self.graph.get(self.peer_id, set())

    # ------------------------------------------------------------
    # Routed messages
    # ------------------------------------------------------------

    # Receive and authenticate one routed message, then check that it is
    # fresh (not replayed, not too old) before it is processed.
    def receive_routed_message(self, connection):
        with connection.makefile("rb") as stream:
            data = stream.readline(MAX_MESSAGE_SIZE + 1)

        if (
            not data
            or len(data) > MAX_MESSAGE_SIZE
            or not data.endswith(b"\n")
        ):
            raise ValueError("Invalid or oversized message")

        (
            sender,
            destination,
            content,
            route,
            tag,
            original_bytes,
            freshness,
        ) = decode_secure_routed_message(data[:-1], with_freshness=True)

        if not verify_hmac(original_bytes, SECRET_KEY, tag):
            raise ValueError("HMAC verification failed")

        # Check freshness only after the HMAC passed, so forged messages
        # cannot fill the nonce memory.
        self.replay_guard.check(freshness)

        return sender, destination, content, route, tag, freshness

    # Forward an authenticated message and return its acknowledgement.
    def forward_routed_message(
        self,
        sender,
        destination,
        content,
        route,
        tag,
        freshness,
    ):
        current_peer = self.peer_id

        # Check whether this peer is the destination.
        if current_peer == destination:
            self.log(f"\nMessage delivered to {current_peer}!")
            self.log(f"Original sender: {sender}")

            # Check whether this is a file request.
            try:
                request = json.loads(content)
            except json.JSONDecodeError:
                request = None

            if isinstance(request, dict) and request.get("type") == "FILE_REQUEST":
                self.handle_file_request(sender, content)
            else:
                self.log(f"Message content: {content}")

            # The ACK repeats this message's msg_id with its own nonce.
            ack_freshness = new_freshness(msg_id=freshness["msg_id"])

            # Create the acknowledgement's original data.
            ack_bytes = canonical_acknowledgement(
                "ok",
                sender,
                destination,
                ack_freshness,
            )

            # Generate an HMAC authentication tag.
            ack_tag = calculate_hmac(
                ack_bytes,
                SECRET_KEY,
            )

            # Return the authenticated acknowledgement.
            return encode_secure_acknowledgement(
                "ok",
                sender,
                destination,
                ack_tag,
                ack_freshness,
            )

        # Find this peer's position in the route.
        try:
            current_index = route.index(current_peer)
        except ValueError:
            raise ValueError(
                "Current peer is not included in the route"
            )

        # Find the next peer in the route.
        if current_index >= len(route) - 1:
            raise ValueError("No next hop available")

        next_hop = route[current_index + 1]

        # Check the overlay links.
        if not self._has_link(next_hop):
            self.refresh_view()

            if not self._has_link(next_hop):
                raise ValueError("Route does not match the overlay links")

        # Find the next peer's network address.
        next_peer = self._peer_record(next_hop)

        if next_peer is None:
            raise ValueError("Unknown next-hop peer")

        next_host, next_port = next_peer["host"], next_peer["port"]

        self.log(
            f"{current_peer} forwarding message "
            f"to {next_hop} ({next_host}:{next_port})"
        )

        # Forward the original authenticated message.
        with socket.create_connection(
            (next_host, next_port),
            timeout=self.socket_timeout,
        ) as connection:

            forwarded_message = encode_secure_routed_message(
                sender,
                destination,
                content,
                route,
                tag,
                freshness,
            )

            connection.sendall(forwarded_message)

            # Wait for the next peer's acknowledgement.
            with connection.makefile("rb") as stream:
                data = read_acknowledgement(stream)

            verify_acknowledgement(
                data, sender, destination,
                freshness["msg_id"], self.replay_guard,
            )

            self.log(
                f"{current_peer} verified acknowledgement "
                f"from {destination}"
            )

            # Forward the original authenticated acknowledgement unchanged.
            return data

    # ------------------------------------------------------------
    # File sharing
    # ------------------------------------------------------------

    # Process a file request and send the requested file to its sender.
    def handle_file_request(self, sender, content):
        try:
            request = json.loads(content)
        except json.JSONDecodeError:
            raise ValueError("Invalid file request JSON")

        if not isinstance(request, dict):
            raise ValueError("File request must be a JSON object")

        if request.get("type") != "FILE_REQUEST":
            raise ValueError("Unknown request type")

        filename = request.get("filename")

        if (
            not isinstance(filename, str)
            or not filename
            or filename in (".", "..")
            or os.path.basename(filename) != filename
            or "/" in filename
            or "\\" in filename
        ):
            raise ValueError("Invalid requested filename")

        requester = self._peer_record(sender)

        if requester is None or not requester.get("file_port"):
            raise ValueError("Unknown requesting peer")

        shared_file_path = os.path.join(self.shared_folder, filename)

        if not os.path.isfile(shared_file_path):
            raise FileNotFoundError(
                f"Requested file not found: {filename}"
            )

        self.log(f"\nFile request received for: {filename}")
        self.log(f"Sending file directly to {sender}...")

        result = send_file(
            requester["host"],
            requester["file_port"],
            shared_file_path,
        )

        self.log(f"File successfully sent to {sender}!")

        return result

    # ------------------------------------------------------------
    # Servers
    # ------------------------------------------------------------

    # Start the peer server and the file server in the background.
    def start(self):
        message_server = self._listen(self.port)
        self.port = message_server.getsockname()[1]

        file_server = self._listen(self.file_port)
        self.file_port = file_server.getsockname()[1]

        self._running.set()

        # Start the separate file-transfer server in a background thread.
        self._start_accept_loop(file_server, self._handle_file_connection)
        self.log(
            f"{self.peer_id} file-transfer server "
            f"listening on {self.bind_host}:{self.file_port}"
        )

        self._start_accept_loop(message_server, self._handle_message_connection)
        self.log(f"{self.peer_id} listening on {self.bind_host}:{self.port}")

        self.register_peer()
        self.refresh_view()

        self.log(f"{self.peer_id} waiting for incoming messages...")
        return self

    # Start the peer and run until the user presses Ctrl+C.
    def start_peer(self):
        self.start()

        try:
            while self._running.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.log(f"\n{self.peer_id} stopped.")
        finally:
            self.stop()

    # Stop both servers.
    def stop(self):
        self._running.clear()

        for server in self._servers:
            try:
                server.close()
            except OSError:
                pass

    # Open a listening socket with a short accept timeout.
    def _listen(self, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        server.bind((self.bind_host, port))
        server.listen(16)

        # A short accept timeout lets the loop notice stop() quickly.
        server.settimeout(0.5)

        self._servers.append(server)
        return server

    # Accept connections and handle each one in its own thread.
    def _start_accept_loop(self, server, handler):
        def accept_loop():
            while self._running.is_set():
                try:
                    connection, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                connection.settimeout(self.socket_timeout)

                threading.Thread(
                    target=handler,
                    args=(connection, address),
                    daemon=True,
                ).start()

        threading.Thread(target=accept_loop, daemon=True).start()

    # Handle one routed message and send back the acknowledgement.
    def _handle_message_connection(self, connection, address):
        self.log(f"\nConnection received from {address}")

        with connection:
            try:
                (
                    sender,
                    destination,
                    content,
                    route,
                    tag,
                    freshness,
                ) = self.receive_routed_message(connection)

                self.log(
                    f"Authenticated routed message: "
                    f"{sender} -> {destination}"
                )

                acknowledgement = self.forward_routed_message(
                    sender,
                    destination,
                    content,
                    route,
                    tag,
                    freshness,
                )

                # Send the authenticated acknowledgement
                # back to the previous peer unchanged.
                connection.sendall(acknowledgement)

            except (
                ValueError,
                OSError,
                KeyError,
                TypeError,
                RuntimeError,
                UnicodeDecodeError,
            ) as error:
                self.log(f"Message processing failed: {error}")

    # Receive one file and print the verification result.
    def _handle_file_connection(self, connection, address):
        self.log(f"\nFile-transfer connection received from {address}")

        with connection:
            try:
                result = receive_file(
                    connection,
                    self.received_folder,
                    replay_guard=self.replay_guard,
                )

                self.log("\nFile received successfully!")
                self.log(f"Filename: {result['filename']}")
                self.log(f"Size: {result['file_size']} bytes")
                self.log(f"SHA-256: {result['sha256']}")
                self.log(f"Status: {result['status']}")

            except Exception as error:
                self.log(f"File transfer failed: {error}")


# Send a secure routed message and wait for delivery confirmation.
def send_routed_message(
    sender,
    destination,
    content,
    route=None,
    excluded=None,
    bootstrap_address=BOOTSTRAP_ADDRESS,
    verbose=True,
):
    peers = get_topology(bootstrap_address)

    if route is None:
        route = shortest_path(build_graph(peers), sender, destination, excluded)

        if route is None:
            raise RuntimeError(f"No route from {sender} to {destination}")

    # New msg_id, nonce and timestamp for this message.
    freshness = new_freshness()

    # Create the original message bytes.
    original_bytes = canonical_routed_message(
        sender,
        destination,
        content,
        route,
        freshness,
    )

    # Generate the HMAC authentication tag.
    tag = calculate_hmac(original_bytes, SECRET_KEY)

    # Find the sender's network address.
    sender_peer = find_peer(peers, sender)

    if sender_peer is None:
        raise ValueError("Unknown sender peer")

    host, port = sender_peer["host"], sender_peer["port"]

    # Connect to the sender peer.
    with socket.create_connection(
        (host, port),
        timeout=config.SOCKET_TIMEOUT,
    ) as connection:

        # Prepare and send the secure routed message.
        message = encode_secure_routed_message(
            sender,
            destination,
            content,
            route,
            tag,
            freshness,
        )

        start_time = time.perf_counter()
        connection.sendall(message)

        if verbose:
            print(f"{sender} sent a message to {destination}")

        # Wait for the delivery acknowledgement.
        with connection.makefile("rb") as stream:
            data = read_acknowledgement(stream)

        end_time = time.perf_counter()

    # The ACK must carry this message's msg_id and be fresh.
    status, ack_sender, ack_destination = verify_acknowledgement(
        data, sender, destination, freshness["msg_id"], ReplayGuard()
    )

    rtt_ms = (end_time - start_time) * 1000

    if verbose:
        print(f"{sender} verified the delivery acknowledgement")
        print("\nAuthenticated delivery acknowledgement received:")
        print(f"Status: {status}")
        print(f"Sender: {ack_sender}")
        print(f"Destination: {ack_destination}")
        print(f"Route: {' -> '.join(route)} ({len(route) - 1} hops)")
        print(f"RTT: {rtt_ms:.3f} ms")

    return {
        "status": status,
        "sender": ack_sender,
        "destination": ack_destination,
        "route": route,
        "hops": len(route) - 1,
        "rtt_ms": rtt_ms,
        "msg_id": freshness["msg_id"],
    }


# Request a file from another peer through the overlay.
def request_file(
    filename,
    requester="Peer A",
    owner="Peer C",
    bootstrap_address=BOOTSTRAP_ADDRESS,
    verbose=True,
):
    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or os.path.basename(filename) != filename
        or "/" in filename
        or "\\" in filename
    ):
        raise ValueError("Invalid filename")

    # Create the file-request message.
    content = json.dumps({
        "type": "FILE_REQUEST",
        "filename": filename,
    })

    if verbose:
        print(f"Requesting file: {filename}")

    # Send the request through the existing routed network.
    return send_routed_message(
        sender=requester,
        destination=owner,
        content=content,
        bootstrap_address=bootstrap_address,
        verbose=verbose,
    )


# Print the registered peers, their links and routing tables.
def show_topology(bootstrap_address=BOOTSTRAP_ADDRESS):
    peers = get_topology(bootstrap_address)
    graph = build_graph(peers)

    print(f"Registered peers: {len(peers)}\n")

    for peer in peers:
        peer_id = peer["peer_id"]
        links = ", ".join(sorted(graph[peer_id])) or "none"

        print(f"{peer_id}  {peer['host']}:{peer['port']}")
        print(f"  links: {links}")

        for destination, next_hop in build_routing_table(graph, peer_id).items():
            print(f"  to {destination}: next hop {next_hop}")

        print()


# Turn "Peer B,Peer C" into a list.
def _parse_list(text):
    return [item.strip() for item in text.split(",") if item.strip()]


# Command-line interface: server, send, request-file, topology.
def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m src.routed_peer")
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("server", help="start a peer")
    server.add_argument("peer_id")
    server.add_argument("--port", type=int)
    server.add_argument("--file-port", type=int)
    server.add_argument("--neighbours", help='e.g. "Peer B,Peer C"')

    send = commands.add_parser("send", help="send a routed message")
    send.add_argument("--from", dest="sender", default="Peer A")
    send.add_argument("--to", dest="destination", default="Peer C")
    send.add_argument("--message", default="Hello from Peer A through Peer B!")
    send.add_argument("--route", help='e.g. "Peer A,Peer B,Peer C"')
    send.add_argument("--avoid", help='peers to avoid, e.g. "Peer B"')

    request = commands.add_parser("request-file", help="request a file")
    request.add_argument("filename")
    request.add_argument("--from", dest="requester", default="Peer A")
    request.add_argument("--to", dest="owner", default="Peer C")

    commands.add_parser("topology", help="show registered peers and routes")

    args = parser.parse_args(argv)

    if args.command == "server":
        RoutedPeer(
            args.peer_id,
            port=args.port,
            file_port=args.file_port,
            neighbours=_parse_list(args.neighbours) if args.neighbours else None,
        ).start_peer()

    elif args.command == "send":
        send_routed_message(
            sender=args.sender,
            destination=args.destination,
            content=args.message,
            route=_parse_list(args.route) if args.route else None,
            excluded=set(_parse_list(args.avoid)) if args.avoid else None,
        )

    elif args.command == "request-file":
        request_file(args.filename, args.requester, args.owner)

    elif args.command == "topology":
        show_topology()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Error: {error}")
