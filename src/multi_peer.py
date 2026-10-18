
import json
import socket
import sys
import time
import csv
import statistics

from src.message import (
    canonical_message,
    encode_secure_message,
    decode_secure_message,
)
from src.security import calculate_hmac, verify_hmac

HOST = "127.0.0.1"
BOOTSTRAP_PORT = 6000
PEER_A_PORT = 5000
PEER_B_PORT = 5001
MAX_MESSAGE_SIZE = 4096

# Demonstration key only. Both peers must use the same key.
SECRET_KEY = b"demo-shared-key-change-later"


def bootstrap_request(request):
    """Send one JSON request to the bootstrap server."""
    with socket.create_connection(
        (HOST, BOOTSTRAP_PORT), timeout=5
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
    """Register this peer's listening address."""
    response = bootstrap_request({
        "action": "register",
        "peer_id": peer_id,
        "host": HOST,
        "port": port,
    })

    print(f"{peer_id} registered at {HOST}:{port}")
    return response


def discover_peers(peer_id):
    """Ask the bootstrap server for other peers."""
    response = bootstrap_request({
        "action": "discover",
        "peer_id": peer_id,
    })

    peers = response.get("peers", [])

    if not isinstance(peers, list):
        raise RuntimeError("Invalid peer list")

    return peers


def receive_secure_message(connection):
    """Read and authenticate one newline-terminated message."""
    with connection.makefile("rb") as stream:
        data = stream.readline(MAX_MESSAGE_SIZE + 1)

    if (
        not data
        or len(data) > MAX_MESSAGE_SIZE
        or not data.endswith(b"\n")
    ):
        raise ValueError("Invalid or oversized message")

    sender, content, tag, original_bytes = (
        decode_secure_message(data[:-1])
    )

    if not verify_hmac(original_bytes, SECRET_KEY, tag):
        raise ValueError("HMAC verification failed")

    return sender, content



def start_peer_a():
    """Listen for and authenticate multiple peer connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PEER_A_PORT))
        server.listen(5)

        print(f"Peer A listening on {HOST}:{PEER_A_PORT}")

        # Register only after the listening socket is ready.
        register_peer("Peer A", PEER_A_PORT)

        print("Waiting for peer connections...")

        # Keep accepting connections until the user stops Peer A.
        while True:
            connection, address = server.accept()

            with connection:
                print(f"\nConnection received from {address}")

                try:
                    sender, content = receive_secure_message(connection)
                except (ValueError, UnicodeDecodeError) as error:
                    print(f"Rejected: invalid message or HMAC. {error}")
                    continue

                print(f"Authenticated message from {sender}: {content}")

                reply = "Message authenticated successfully!"
                reply_bytes = canonical_message("Peer A", reply)
                reply_tag = calculate_hmac(reply_bytes, SECRET_KEY)

                connection.sendall(
                    encode_secure_message("Peer A", reply, reply_tag)
                )

                print("Authenticated reply sent to Peer B.")

def start_peer_b():
    """Register, discover Peer A, and connect to it."""
    # Keep a listening socket open so the advertised address is real.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PEER_B_PORT))
        listener.listen(5)

        print(f"Peer B listening on {HOST}:{PEER_B_PORT}")
        register_peer("Peer B", PEER_B_PORT)

        peers = discover_peers("Peer B")
        peer_a = next(
            (peer for peer in peers if peer.get("peer_id") == "Peer A"),
            None,
        )

        if peer_a is None:
            print("Peer A was not found. Start Peer A first.")
            return

        target_host = peer_a.get("host")
        target_port = peer_a.get("port")

        if (
            not isinstance(target_host, str)
            or isinstance(target_port, bool)
            or not isinstance(target_port, int)
            or not 1 <= target_port <= 65535
        ):
            print("Bootstrap returned an invalid Peer A address.")
            return

        
        message = input("Enter a message to send to Peer A: ")
        number_of_tests = 10
        rtt_results = []
        csv_file = "rtt_results.csv"

        with open(csv_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Test Number", "Message", "RTT (ms)", "Status"])

        for test_number in range(1, number_of_tests + 1):
            test_message = f"{message} (test {test_number})"
            message_bytes = canonical_message("Peer B", test_message)
            tag = calculate_hmac(message_bytes, SECRET_KEY)

            try:
                with socket.create_connection(
                    (target_host, target_port), timeout=5
                ) as connection:
                    start_time = time.perf_counter()

                    connection.sendall(
                        encode_secure_message(
                            "Peer B", test_message, tag
                        )
                    )

                    sender, content = receive_secure_message(
                        connection
                    )

                    end_time = time.perf_counter()

                if sender != "Peer A":
                    print("Rejected: unexpected reply sender.")
                    continue

                rtt_ms = (end_time - start_time) * 1000
                rtt_results.append(rtt_ms)
                with open(csv_file, "a", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow([
                        test_number,
                        test_message,
                        f"{rtt_ms:.3f}",
                        "Success"
                    ])

                print(
                    f"Test {test_number}: "
                    f"Verified reply from {sender}: {content}"
                )
                print(f"  RTT: {rtt_ms:.3f} ms")

            except (OSError, ValueError, UnicodeDecodeError) as error:
                print(f"Test {test_number} failed: {error}")

                with open(csv_file, "a", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow([
                        test_number,
                        test_message,
                        "",
                        f"Failed: {error}"
                    ])

        if rtt_results:
            average_rtt = sum(rtt_results) / len(rtt_results)
            median_rtt = statistics.median(rtt_results)
            std_dev_rtt = statistics.pstdev(rtt_results)

            print("\n--- RTT Performance Summary ---")
            print(f"Successful tests: {len(rtt_results)}/{number_of_tests}")
            print(f"Average RTT: {average_rtt:.3f} ms")
            print(f"Minimum RTT: {min(rtt_results):.3f} ms")
            print(f"Maximum RTT: {max(rtt_results):.3f} ms")
            print(f"Median RTT: {median_rtt:.3f} ms")
            print(f"Population standard deviation: {std_dev_rtt:.3f} ms")
        else:
            print("No successful RTT measurements were recorded.")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].upper() not in {"A", "B"}:
        print("Usage: python -m src.multi_peer A")
        print("   or: python -m src.multi_peer B")
        raise SystemExit(1)

    try:
        if sys.argv[1].upper() == "A":
            start_peer_a()
        else:
            start_peer_b()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Peer error: {error}")
