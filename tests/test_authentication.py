"""
New file: tests for peer authentication.

Checks key creation, signing and checking, the bootstrap server's join
control (only trusted, correctly signed peers may register), and runs
real peers to show that impersonation, unsigned messages, forged
acknowledgements and files signed by the wrong peer are all rejected.
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
from src.filesharing import canonical_file_metadata, receive_file, send_file
from src.identity import (
    TRUST_FILE,
    AuthenticationError,
    generate_keys,
    load_identity,
    load_trust_store,
    sign_request,
    verify_request,
)
from src.message import (
    canonical_acknowledgement,
    canonical_routed_message,
    encode_secure_acknowledgement,
    encode_secure_routed_message,
)
from src.replay import ReplayGuard, new_freshness
from src.routed_peer import RoutedPeer, send_routed_message, verify_acknowledgement
from src.security import calculate_hmac

KEY = config.SECRET_KEY


# Build a routed message with a valid HMAC, signed by 'signer' (or unsigned).
def routed_line(sender, destination, content, route, signer=None):
    freshness = new_freshness()
    original = canonical_routed_message(sender, destination, content, route, freshness)
    tag = calculate_hmac(original, KEY)
    signature = signer.sign(original) if signer else None
    return encode_secure_routed_message(
        sender, destination, content, route, tag, freshness, signature
    )


# Send raw bytes to a peer and return its one-line reply (b"" if none).
def send_raw(address, payload):
    with socket.create_connection(address, timeout=5) as connection:
        connection.sendall(payload)
        with connection.makefile("rb") as stream:
            return stream.readline(config.MAX_MESSAGE_SIZE + 1)


# A registration request as a peer would send it.
def registration(peer_id, port=5000):
    return {
        "action": "register",
        "peer_id": peer_id,
        "host": "127.0.0.1",
        "port": port,
        "freshness": new_freshness(),
    }


# Keys, the trusted list, signing and checking.
class TestIdentity(unittest.TestCase):

    def setUp(self):
        self.keys_dir = tempfile.mkdtemp()
        generate_keys(["A", "B"], self.keys_dir)
        self.trust = load_trust_store(self.keys_dir)
        self.a = load_identity("A", self.keys_dir)
        self.b = load_identity("B", self.keys_dir)

    def tearDown(self):
        shutil.rmtree(self.keys_dir, ignore_errors=True)

    def test_keys_and_trusted_list_created(self):
        self.assertTrue(os.path.isfile(os.path.join(self.keys_dir, "A.key")))
        self.assertEqual(self.trust.peers(), ["A", "B"])

    def test_trusted_list_holds_only_public_keys(self):
        with open(os.path.join(self.keys_dir, TRUST_FILE), encoding="utf-8") as file:
            trusted = json.load(file)

        with open(os.path.join(self.keys_dir, "A.key"), encoding="utf-8") as file:
            private_hex = file.read().strip()

        self.assertNotIn(private_hex, json.dumps(trusted))

    def test_running_setup_again_keeps_keys(self):
        before = self.a.sign(b"x")
        generate_keys(["A", "B"], self.keys_dir)
        again = load_identity("A", self.keys_dir)
        load_trust_store(self.keys_dir).verify("A", b"x", before)
        self.assertEqual(again.sign(b"x"), before)

    def test_valid_signature_accepted(self):
        self.trust.verify("A", b"hello", self.a.sign(b"hello"))

    def test_signature_from_other_peer_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.trust.verify("A", b"hello", self.b.sign(b"hello"))

    def test_changed_data_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.trust.verify("A", b"hello!", self.a.sign(b"hello"))

    def test_unknown_peer_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.trust.verify("Z", b"hello", self.a.sign(b"hello"))

    def test_missing_signature_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.trust.verify("A", b"hello", None)

    def test_signed_request_checked(self):
        request = sign_request(registration("A"), self.a)
        verify_request(request, self.trust)

        request["port"] = 6666
        with self.assertRaises(AuthenticationError):
            verify_request(request, self.trust)

    def test_missing_key_gives_clear_error(self):
        with self.assertRaises(AuthenticationError):
            load_identity("Nobody", self.keys_dir)


# Join control at the bootstrap server (no network needed).
class TestJoinControl(unittest.TestCase):

    def setUp(self):
        self.keys_dir = tempfile.mkdtemp()
        self.outsider_dir = tempfile.mkdtemp()
        generate_keys(["A", "B"], self.keys_dir)
        generate_keys(["X"], self.outsider_dir)
        self.server = BootstrapServer(verbose=False, keys_dir=self.keys_dir)
        self.a = load_identity("A", self.keys_dir)

    def tearDown(self):
        shutil.rmtree(self.keys_dir, ignore_errors=True)
        shutil.rmtree(self.outsider_dir, ignore_errors=True)

    def register(self, request):
        return self.server.process_request(request, ("test", 0))

    def test_trusted_peer_can_join(self):
        response = self.register(sign_request(registration("A"), self.a))
        self.assertEqual(response["status"], "ok")

    def test_unknown_peer_rejected(self):
        outsider = load_identity("X", self.outsider_dir)
        response = self.register(sign_request(registration("X"), outsider))
        self.assertEqual(response["status"], "error")
        self.assertIn("Unauthorized", response["message"])

    def test_unsigned_registration_rejected(self):
        response = self.register(registration("A"))
        self.assertEqual(response["status"], "error")

    def test_registering_as_another_peer_rejected(self):
        # A signs a registration that claims to be B.
        response = self.register(sign_request(registration("B"), self.a))
        self.assertEqual(response["status"], "error")

    def test_replayed_registration_rejected(self):
        request = sign_request(registration("A"), self.a)
        self.assertEqual(self.register(request)["status"], "ok")
        self.assertEqual(self.register(request)["status"], "error")

    def test_rejected_peer_not_listed(self):
        self.register(registration("A"))
        self.assertEqual(self.server.directory.get_peers(), [])


# Files must be signed by the peer named as their sender.
class TestSignedFiles(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.keys_dir = os.path.join(self.work_dir, "keys")
        generate_keys(["A", "C"], self.keys_dir)
        self.trust = load_trust_store(self.keys_dir)
        self.file_path = os.path.join(self.work_dir, "data.txt")
        with open(self.file_path, "wb") as file:
            file.write(b"signed file\n")

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    # Record what send_file() puts on the wire.
    def capture(self, identity):
        captured = []
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)

            def collect():
                connection, _ = server.accept()
                with connection:
                    chunks = []
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                captured.append(b"".join(chunks))

            thread = threading.Thread(target=collect)
            thread.start()
            send_file("127.0.0.1", server.getsockname()[1], self.file_path, identity=identity)
            thread.join(5)
        return captured[0]

    def deliver(self, wire):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(wire)
            sender.shutdown(socket.SHUT_WR)
            return receive_file(receiver, os.path.join(self.work_dir, "in"),
                                ReplayGuard(), self.trust)

    def test_signed_file_accepted(self):
        wire = self.capture(load_identity("C", self.keys_dir))
        self.assertEqual(self.deliver(wire)["status"], "verified")

    def test_file_claiming_other_sender_rejected(self):
        # A signs the file, then changes the sender name to C and fixes
        # the HMAC (an insider knows the shared key) - the signature still
        # belongs to A, so it is rejected.
        wire = self.capture(load_identity("A", self.keys_dir))
        header, body = wire.split(b"\n", 1)
        envelope = json.loads(header)
        envelope["metadata"]["sender"] = "C"
        envelope["tag"] = calculate_hmac(canonical_file_metadata(envelope["metadata"]), KEY)
        forged = json.dumps(envelope).encode("utf-8") + b"\n" + body

        with self.assertRaises(AuthenticationError):
            self.deliver(forged)

    def test_unsigned_file_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.deliver(self.capture(None))


# Real bootstrap server and peers A - B - C.
class TestLiveAuthentication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp()
        cls.keys_dir = os.path.join(cls.work_dir, "keys")
        cls.outsider_dir = os.path.join(cls.work_dir, "outsider")
        generate_keys(["A", "B", "C"], cls.keys_dir)
        generate_keys(["X"], cls.outsider_dir)

        cls.trust = load_trust_store(cls.keys_dir)
        cls.ids = {p: load_identity(p, cls.keys_dir) for p in ("A", "B", "C")}

        cls.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False, keys_dir=cls.keys_dir
        ).start()
        cls.bootstrap_address = ("127.0.0.1", cls.bootstrap.port)

        cls.peers = {}
        for peer_id, neighbours in {"A": ["B"], "B": ["A", "C"], "C": ["B"]}.items():
            cls.peers[peer_id] = RoutedPeer(
                peer_id, port=0, file_port=0, neighbours=neighbours,
                bind_host="127.0.0.1", advertised_host="127.0.0.1",
                bootstrap_address=cls.bootstrap_address, socket_timeout=2.0,
                shared_folder=cls.work_dir,
                received_folder=os.path.join(cls.work_dir, "recv", peer_id),
                verbose=False, keys_dir=cls.keys_dir,
            ).start()

        cls.address_a = ("127.0.0.1", cls.peers["A"].port)
        cls.route = ["A", "B", "C"]

    @classmethod
    def tearDownClass(cls):
        for peer in cls.peers.values():
            peer.stop()
        cls.bootstrap.stop()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def test_signed_message_delivered(self):
        result = send_routed_message(
            "A", "C", "hello", bootstrap_address=self.bootstrap_address,
            verbose=False, keys_dir=self.keys_dir,
        )
        self.assertEqual(result["status"], "ok")

    def test_correctly_signed_raw_message_delivered(self):
        reply = send_raw(self.address_a, routed_line("A", "C", "ok", self.route, self.ids["A"]))
        self.assertTrue(reply)

    def test_impersonation_rejected(self):
        # C sends a message that claims to come from A, signed with C's key.
        line = routed_line("A", "C", "I am A", self.route, self.ids["C"])
        self.assertEqual(send_raw(self.address_a, line), b"")

    def test_unsigned_message_rejected(self):
        # Valid HMAC (shared key) but no signature: not enough any more.
        line = routed_line("A", "C", "no signature", self.route)
        self.assertEqual(send_raw(self.address_a, line), b"")

    def test_forged_acknowledgement_rejected(self):
        # An ACK for a message to C, but signed by A instead of C.
        freshness = new_freshness()
        ack_freshness = new_freshness(msg_id=freshness["msg_id"])
        ack_bytes = canonical_acknowledgement("ok", "A", "C", ack_freshness)
        forged = encode_secure_acknowledgement(
            "ok", "A", "C", calculate_hmac(ack_bytes, KEY),
            ack_freshness, self.ids["A"].sign(ack_bytes),
        )

        with self.assertRaises(AuthenticationError):
            verify_acknowledgement(forged, "A", "C", freshness["msg_id"],
                                   ReplayGuard(), self.trust)

    def test_untrusted_peer_cannot_join(self):
        outsider = RoutedPeer(
            "X", port=0, file_port=0, neighbours=["A"],
            bind_host="127.0.0.1", advertised_host="127.0.0.1",
            bootstrap_address=self.bootstrap_address, verbose=False,
            keys_dir=self.outsider_dir,
        )
        try:
            with self.assertRaises(RuntimeError):
                outsider.start()
        finally:
            outsider.stop()


if __name__ == "__main__":
    unittest.main()
