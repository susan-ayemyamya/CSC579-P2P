
import json
import socket
import threading

from src.message import (
    canonical_routed_message,
    encode_secure_routed_message,
    decode_secure_routed_message,
    canonical_acknowledgement,
    encode_secure_acknowledgement,
    decode_secure_acknowledgement,
)

from src.security import calculate_hmac, verify_hmac
from src.routing import get_next_hop


# Peer network configuration
HOST = "127.0.0.1"

BOOTSTRAP_HOST = "127.0.0.1"
BOOTSTRAP_PORT = 6000

MAX_MESSAGE_SIZE = 4096

# Demonstration key: all peers use the same key.
SECRET_KEY = b"demo-shared-key-change-later"


# Peer addresses for our localhost demonstration
PEER_ADDRESSES = {
    "Peer A": ("127.0.0.1", 5000),
    "Peer B": ("127.0.0.1", 5001),
    "Peer C": ("127.0.0.1", 5002),
}


# Routing tables
ROUTING_TABLES = {
    "Peer A": {
        "Peer C": "Peer B",
    },

    "Peer B": {
        "Peer C": "Peer C",
    },

    "Peer C": {},
}


def bootstrap_request(request):
    """Send one JSON request to the bootstrap server."""

    with socket.create_connection(
        (BOOTSTRAP_HOST, BOOTSTRAP_PORT),
        timeout=5
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


def register_peer(peer_id, port):
    """Register this peer with the bootstrap server."""

    response = bootstrap_request({
        "action": "register",
        "peer_id": peer_id,
        "host": HOST,
        "port": port,
    })

    print(
        f"{peer_id} registered at {HOST}:{port}"
    )

    return response


def discover_peers(peer_id):
    """Discover other peers through the bootstrap server."""

    response = bootstrap_request({
        "action": "discover",
        "peer_id": peer_id,
    })

    peers = response.get("peers", [])

    if not isinstance(peers, list):
        raise RuntimeError("Invalid peer list")

    return peers


def receive_routed_message(connection):
    """Receive and authenticate one routed message."""

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
    ) = decode_secure_routed_message(data[:-1])

    if not verify_hmac(original_bytes, SECRET_KEY, tag):
        raise ValueError("HMAC verification failed")

    return sender, destination, content, route, tag



def forward_routed_message(
    current_peer,
    sender,
    destination,
    content,
    route,
    tag,
):
    """Forward an authenticated message and return its acknowledgement."""

        # Check whether this peer is the destination.
    if current_peer == destination:
        print(f"\nMessage delivered to {current_peer}!")
        print(f"Original sender: {sender}")
        print(f"Message content: {content}")

        # Create the acknowledgement's original data.
        ack_bytes = canonical_acknowledgement(
            "ok",
            sender,
            destination,
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

    # Check the routing table.
    configured_next_hop = get_next_hop(
        destination,
        ROUTING_TABLES[current_peer],
    )

    if configured_next_hop != next_hop:
        raise ValueError("Route does not match routing table")

    # Find the next peer's network address.
    if next_hop not in PEER_ADDRESSES:
        raise ValueError("Unknown next-hop peer")

    next_host, next_port = PEER_ADDRESSES[next_hop]

    print(
        f"{current_peer} forwarding message "
        f"to {next_hop} ({next_host}:{next_port})"
    )

    # Forward the original authenticated message.
    with socket.create_connection(
        (next_host, next_port),
        timeout=5,
    ) as connection:

        forwarded_message = encode_secure_routed_message(
            sender,
            destination,
            content,
            route,
            tag,
        )

        connection.sendall(forwarded_message)

        # Wait for the next peer's acknowledgement.
        with connection.makefile("rb") as stream:
            data = stream.readline(MAX_MESSAGE_SIZE + 1)

        if (
            not data
            or len(data) > MAX_MESSAGE_SIZE
            or not data.endswith(b"\n")
        ):
            raise ValueError("Invalid delivery acknowledgement")

                # Decode the authenticated acknowledgement.
        (
            status,
            ack_sender,
            ack_destination,
            ack_tag,
            ack_original_bytes,
        ) = decode_secure_acknowledgement(data[:-1])

        # Verify the acknowledgement's HMAC.
        if not verify_hmac(
            ack_original_bytes,
            SECRET_KEY,
            ack_tag,
        ):
            raise ValueError("Acknowledgement HMAC verification failed")
        print(
            f"{current_peer} verified acknowledgement "
            f"from {ack_destination}"
        )

        # Confirm that the acknowledgement matches the original message.
        if (
            status != "ok"
            or ack_sender != sender
            or ack_destination != destination
        ):
            raise ValueError(
                "Acknowledgement does not match routed message"
            )

        # Forward the original authenticated acknowledgement unchanged.
        return data

def start_peer(peer_id):
    """Start a peer server and handle incoming routed messages."""

    if peer_id not in PEER_ADDRESSES:
        raise ValueError("Unknown peer ID")

    host, port = PEER_ADDRESSES[peer_id]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.bind((host, port))
        server.listen(5)

        print(f"{peer_id} listening on {host}:{port}")

        register_peer(peer_id, port)

        print(f"{peer_id} waiting for incoming messages...")

        while True:
            connection, address = server.accept()

            print(f"\nConnection received from {address}")

            with connection:
                try:
                    (
                        sender,
                        destination,
                        content,
                        route,
                        tag,
                    ) = receive_routed_message(connection)

                    print(
                        f"Authenticated routed message: "
                        f"{sender} -> {destination}"
                    )

                    acknowledgement = forward_routed_message(
                        peer_id,
                        sender,
                        destination,
                        content,
                        route,
                        tag,
                    )

                    # Send the authenticated acknowledgement
                    # back to the previous peer unchanged.
                    connection.sendall(acknowledgement)

                except (
                    ValueError,
                    OSError,
                    KeyError,
                ) as error:
                    print(f"Message processing failed: {error}")



def send_routed_message(
    sender,
    destination,
    content,
    route,
):
    """Send a secure routed message and wait for delivery confirmation."""

    # Create the original message bytes.
    original_bytes = canonical_routed_message(
        sender,
        destination,
        content,
        route,
    )

    # Generate the HMAC authentication tag.
    tag = calculate_hmac(original_bytes, SECRET_KEY)

    # Find the sender's network address.
    if sender not in PEER_ADDRESSES:
        raise ValueError("Unknown sender peer")

    host, port = PEER_ADDRESSES[sender]

    # Connect to the sender peer.
    with socket.create_connection(
        (host, port),
        timeout=5,
    ) as connection:

        # Prepare and send the secure routed message.
        message = encode_secure_routed_message(
            sender,
            destination,
            content,
            route,
            tag,
        )

        connection.sendall(message)

        print(f"{sender} sent a message to {destination}")

        # Wait for the delivery acknowledgement.
        with connection.makefile("rb") as stream:
            data = stream.readline(MAX_MESSAGE_SIZE + 1)

        if (
            not data
            or len(data) > MAX_MESSAGE_SIZE
            or not data.endswith(b"\n")
        ):
            raise ValueError("Invalid delivery acknowledgement")

                # Decode the authenticated acknowledgement.
        (
            status,
            ack_sender,
            ack_destination,
            ack_tag,
            ack_original_bytes,
        ) = decode_secure_acknowledgement(data[:-1])

        # Verify the acknowledgement's HMAC.
        if not verify_hmac(
            ack_original_bytes,
            SECRET_KEY,
            ack_tag,
        ):
            raise ValueError("Acknowledgement HMAC verification failed")
        print(f"{sender} verified the delivery acknowledgement")

        # Confirm that the acknowledgement matches the original message.
        if (
            status != "ok"
            or ack_sender != sender
            or ack_destination != destination
        ):
            raise ValueError(
                "Acknowledgement does not match original message"
            )

        print("\nAuthenticated delivery acknowledgement received:")
        print(f"Status: {status}")
        print(f"Sender: {ack_sender}")
        print(f"Destination: {ack_destination}")

        return {
            "status": status,
            "sender": ack_sender,
            "destination": ack_destination,
        }



if __name__ == "__main__":

    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m src.routed_peer server <Peer ID>")
        print("  python -m src.routed_peer send")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "server":

        if len(sys.argv) != 3:
            print("Please specify a peer ID.")
            sys.exit(1)

        peer_id = sys.argv[2]

        start_peer(peer_id)

    elif command == "send":

        send_routed_message(
            sender="Peer A",
            destination="Peer C",
            content="Hello from Peer A through Peer B!",
            route=["Peer A", "Peer B", "Peer C"],
        )

    else:
        print("Unknown command.")
        sys.exit(1)
