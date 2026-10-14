
import json
import socket

HOST = "127.0.0.1"
PORT = 6000


def send_request(request):
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        client.sendall(
            json.dumps(request).encode("utf-8") + b"\n"
        )

        with client.makefile("rb") as stream:
            response = stream.readline(4097)

    if not response or len(response) > 4096:
        raise RuntimeError("Invalid response from bootstrap server")

    return json.loads(response.decode("utf-8"))


def main():
    # Register Peer A.
    response_a = send_request({
        "action": "register",
        "peer_id": "Peer A",
        "host": "127.0.0.1",
        "port": 5000,
    })
    print("Peer A registration:", response_a)

    # Register Peer B.
    response_b = send_request({
        "action": "register",
        "peer_id": "Peer B",
        "host": "127.0.0.1",
        "port": 5001,
    })
    print("Peer B registration:", response_b)

    # Ask Peer A to discover other peers.
    discovery = send_request({
        "action": "discover",
        "peer_id": "Peer A",
    })
    print("Peer A discovers:", discovery)

    peer_ids = [
        peer["peer_id"]
        for peer in discovery.get("peers", [])
    ]

    if discovery.get("status") == "ok" and "Peer B" in peer_ids:
        print("SUCCESS: Peer A discovered Peer B.")
    else:
        print("FAILURE: Peer A could not discover Peer B.")


if __name__ == "__main__":
    main()
