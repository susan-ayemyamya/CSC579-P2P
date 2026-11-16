"""
New file: tests for replay protection.

Checks the ReplayGuard on its own (fresh, replayed, old and future
messages), that the freshness fields are covered by the HMAC, and runs
real peers to show that a replayed message, a stale message, a replayed
acknowledgement and a replayed file transfer are all rejected while
normal traffic still works.
"""

import json
import os
import shutil
import socket
import tempfile
import threading
import unittest

from src import config
from src.bootstrap import BootstrapServer
from src.identity import generate_keys, load_identity, load_trust_store
from src.filesharing import receive_file, send_file
from src.message import (
    canonical_routed_message,
    decode_secure_routed_message,
    encode_secure_routed_message,
)
from src.replay import ReplayError, ReplayGuard, new_freshness, now_ms
from src.routed_peer import (
    RoutedPeer,
    send_routed_message,
    verify_acknowledgement,
)
from src.security import calculate_hmac, verify_hmac

KEY = config.SECRET_KEY


# A clock the tests can move by hand (milliseconds).
class FakeClock:
    def __init__(self, start=1_000_000):
        self.now = start

    def __call__(self):
        return self.now


# Build a valid, signed routed message with the given freshness fields.
# With an identity, it is also signed with that peer's private key.
def signed_message(sender, destination, content, route, freshness, identity=None):
    original = canonical_routed_message(sender, destination, content, route, freshness)
    tag = calculate_hmac(original, KEY)
    signature = identity.sign(original) if identity else None
    return encode_secure_routed_message(
        sender, destination, content, route, tag, freshness, signature
    )


# Send raw bytes to a peer and return its one-line reply (b"" if none).
def send_raw(address, payload):
    with socket.create_connection(address, timeout=5) as connection:
        connection.sendall(payload)
        with connection.makefile("rb") as stream:
            return stream.readline(config.MAX_MESSAGE_SIZE + 1)


# ReplayGuard on its own, with a fake clock.
class TestReplayGuard(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock()
        self.guard = ReplayGuard(window=30, clock=self.clock)

    def fields(self, offset_ms=0):
        fields = new_freshness()
        fields["timestamp"] = self.clock.now + offset_ms
        return fields

    def test_fresh_message_accepted(self):
        self.guard.check(self.fields())

    def test_same_nonce_rejected(self):
        fields = self.fields()
        self.guard.check(fields)

        with self.assertRaises(ReplayError):
            self.guard.check(fields)

    def test_old_message_rejected(self):
        with self.assertRaises(ReplayError):
            self.guard.check(self.fields(offset_ms=-31_000))

    def test_future_message_rejected(self):
        with self.assertRaises(ReplayError):
            self.guard.check(self.fields(offset_ms=31_000))

    def test_old_nonces_are_forgotten(self):
        self.guard.check(self.fields())
        self.assertEqual(len(self.guard), 1)

        # Two windows later the nonce is no longer needed in memory.
        self.clock.now += 61_000
        self.guard.check(self.fields())
        self.assertEqual(len(self.guard), 1)

    def test_invalid_fields_rejected(self):
        for bad in (
            None,
            {"msg_id": "x", "nonce": "a" * 32, "timestamp": 1},
            {"msg_id": "a" * 32, "nonce": "z" * 32, "timestamp": 1},
            {"msg_id": "a" * 32, "nonce": "a" * 32, "timestamp": True},
        ):
            with self.assertRaises(ValueError):
                self.guard.check(bad)


# The freshness fields are part of the signed data.
class TestSignedFreshness(unittest.TestCase):

    def setUp(self):
        self.route = ["A", "B", "C"]
        self.freshness = new_freshness()
        self.line = signed_message("A", "C", "hi", self.route, self.freshness)

    def test_valid_message_verifies(self):
        decoded = decode_secure_routed_message(self.line[:-1], with_freshness=True)
        self.assertTrue(verify_hmac(decoded[5], KEY, decoded[4]))
        self.assertEqual(decoded[6], self.freshness)

    def test_changed_nonce_breaks_hmac(self):
        envelope = json.loads(self.line)
        envelope["freshness"]["nonce"] = "b" * 32
        tampered = json.dumps(envelope).encode("utf-8")

        decoded = decode_secure_routed_message(tampered, with_freshness=True)
        self.assertFalse(verify_hmac(decoded[5], KEY, decoded[4]))

    def test_changed_timestamp_breaks_hmac(self):
        envelope = json.loads(self.line)
        envelope["freshness"]["timestamp"] = now_ms() + 1
        tampered = json.dumps(envelope).encode("utf-8")

        decoded = decode_secure_routed_message(tampered, with_freshness=True)
        self.assertFalse(verify_hmac(decoded[5], KEY, decoded[4]))

    def test_secure_decode_requires_freshness(self):
        original = canonical_routed_message("A", "C", "hi", self.route)
        tag = calculate_hmac(original, KEY)
        old_style = encode_secure_routed_message("A", "C", "hi", self.route, tag)

        with self.assertRaises(ValueError):
            decode_secure_routed_message(old_style[:-1], with_freshness=True)


# A replayed file transfer is rejected by the receiver's guard.
class TestFileReplay(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.file_path = os.path.join(self.work_dir, "data.txt")

        with open(self.file_path, "wb") as file:
            file.write(b"replay test file\n")

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    # Capture exactly what send_file() puts on the wire.
    def capture_transfer(self):
        captured = []

        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)

            def collect():
                connection, _ = server.accept()
                chunks = []
                with connection:
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                captured.append(b"".join(chunks))

            thread = threading.Thread(target=collect)
            thread.start()
            send_file("127.0.0.1", server.getsockname()[1], self.file_path)
            thread.join(5)

        return captured[0]

    # Feed recorded bytes into receive_file() as if they came from the network.
    def deliver(self, wire_bytes, guard):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(wire_bytes)
            sender.shutdown(socket.SHUT_WR)
            return receive_file(receiver, os.path.join(self.work_dir, "in"), replay_guard=guard)

    def test_replayed_file_transfer_rejected(self):
        wire = self.capture_transfer()
        guard = ReplayGuard()

        self.assertEqual(self.deliver(wire, guard)["status"], "verified")

        with self.assertRaises(ReplayError):
            self.deliver(wire, guard)

    def test_file_without_freshness_rejected_by_peer(self):
        wire = self.capture_transfer()
        header, body = wire.split(b"\n", 1)
        envelope = json.loads(header)
        del envelope["metadata"]["freshness"]
        envelope["tag"] = calculate_hmac(
            json.dumps(envelope["metadata"], sort_keys=True, separators=(",", ":")).encode("utf-8"),
            KEY,
        )
        stripped = json.dumps(envelope).encode("utf-8") + b"\n" + body

        with self.assertRaises(ValueError):
            self.deliver(stripped, ReplayGuard())


# Real bootstrap server and three peers A - B - C.
class TestLiveReplay(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp()

        # Keys for the test peers; A's key is used to build captured messages.
        cls.keys_dir = os.path.join(cls.work_dir, "keys")
        generate_keys(["A", "B", "C"], cls.keys_dir)
        cls.identity_a = load_identity("A", cls.keys_dir)
        cls.trust = load_trust_store(cls.keys_dir)

        cls.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False, keys_dir=cls.keys_dir
        ).start()
        cls.bootstrap_address = ("127.0.0.1", cls.bootstrap.port)

        cls.peers = {}
        for peer_id, neighbours in {"A": ["B"], "B": ["A", "C"], "C": ["B"]}.items():
            cls.peers[peer_id] = RoutedPeer(
                peer_id,
                port=0,
                file_port=0,
                neighbours=neighbours,
                bind_host="127.0.0.1",
                advertised_host="127.0.0.1",
                bootstrap_address=cls.bootstrap_address,
                socket_timeout=2.0,
                shared_folder=cls.work_dir,
                received_folder=os.path.join(cls.work_dir, "recv", peer_id),
                verbose=False,
                keys_dir=cls.keys_dir,
            ).start()

        cls.address_a = ("127.0.0.1", cls.peers["A"].port)

    @classmethod
    def tearDownClass(cls):
        for peer in cls.peers.values():
            peer.stop()
        cls.bootstrap.stop()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def test_normal_message_still_delivered(self):
        result = send_routed_message(
            "A", "C", "hello", bootstrap_address=self.bootstrap_address,
            verbose=False, keys_dir=self.keys_dir,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["msg_id"]), 32)

    def test_replayed_message_rejected(self):
        line = signed_message("A", "C", "pay 10", ["A", "B", "C"], new_freshness(),
                              self.identity_a)

        first = send_raw(self.address_a, line)
        second = send_raw(self.address_a, line)

        self.assertTrue(first, "the original message should be acknowledged")
        self.assertEqual(second, b"", "the replayed copy must be dropped")

    def test_old_message_rejected(self):
        freshness = new_freshness()
        freshness["timestamp"] -= 120_000  # two minutes old

        reply = send_raw(self.address_a, signed_message(
            "A", "C", "old", ["A", "B", "C"], freshness, self.identity_a))
        self.assertEqual(reply, b"")

    def test_replayed_ack_rejected(self):
        freshness = new_freshness()
        ack = send_raw(self.address_a, signed_message(
            "A", "C", "x", ["A", "B", "C"], freshness, self.identity_a))

        guard = ReplayGuard()
        verify_acknowledgement(ack, "A", "C", freshness["msg_id"], guard, self.trust)

        # The same ACK shown a second time is a replay.
        with self.assertRaises(ReplayError):
            verify_acknowledgement(ack, "A", "C", freshness["msg_id"], guard, self.trust)

    def test_ack_for_another_message_rejected(self):
        first = new_freshness()
        ack = send_raw(self.address_a, signed_message(
            "A", "C", "one", ["A", "B", "C"], first, self.identity_a))

        # An old ACK cannot confirm a new message.
        with self.assertRaises(ReplayError):
            verify_acknowledgement(ack, "A", "C", new_freshness()["msg_id"],
                                   ReplayGuard(), self.trust)


if __name__ == "__main__":
    unittest.main()
