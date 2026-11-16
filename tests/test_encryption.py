"""
New file: tests for end-to-end encryption.

Checks the encryption functions on their own, the key upgrade from
Step 4 key files, encrypted file transfers, and runs real peers to show
that a peer in the middle of a route only sees ciphertext, that plain
or wrongly encrypted messages are refused, and that files still arrive
intact.
"""

import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src import config
from src.bootstrap import BootstrapServer
from src.encryption import (
    DecryptionError,
    decrypt_content,
    decrypt_with,
    encrypt_content,
    encrypt_for,
    is_encrypted,
    message_context,
)
from src.filesharing import receive_file, send_file
from src.identity import (
    TRUST_FILE,
    AuthenticationError,
    TrustStore,
    generate_keys,
    load_identity,
    load_trust_store,
)
from src.message import canonical_routed_message, encode_secure_routed_message
from src.replay import ReplayGuard, new_freshness
from src.routed_peer import RoutedPeer, request_file, send_routed_message
from src.security import calculate_hmac

KEY = config.SECRET_KEY
SECRET = "meet at 10, door code 4321"


# Send raw bytes to a peer and return its one-line reply (b"" if none).
def send_raw(address, payload):
    with socket.create_connection(address, timeout=5) as connection:
        connection.sendall(payload)
        with connection.makefile("rb") as stream:
            return stream.readline(config.MAX_MESSAGE_SIZE + 1)


# The encryption functions on their own.
class TestEncryptionFunctions(unittest.TestCase):

    def setUp(self):
        self.key = X25519PrivateKey.generate()
        self.context = message_context("A", "C", "a" * 32)

    def test_round_trip(self):
        content = encrypt_content(SECRET, self.key.public_key(), self.context)
        self.assertEqual(decrypt_content(content, self.key, self.context), SECRET)

    def test_ciphertext_hides_the_text(self):
        content = encrypt_content(SECRET, self.key.public_key(), self.context)
        self.assertNotIn("door code", content)
        self.assertTrue(is_encrypted(content))

    def test_same_text_encrypts_differently_each_time(self):
        first = encrypt_content(SECRET, self.key.public_key(), self.context)
        second = encrypt_content(SECRET, self.key.public_key(), self.context)
        self.assertNotEqual(first, second)

    def test_wrong_key_fails(self):
        content = encrypt_content(SECRET, self.key.public_key(), self.context)
        with self.assertRaises(DecryptionError):
            decrypt_content(content, X25519PrivateKey.generate(), self.context)

    def test_other_message_context_fails(self):
        content = encrypt_content(SECRET, self.key.public_key(), self.context)
        with self.assertRaises(DecryptionError):
            decrypt_content(content, self.key, message_context("A", "C", "b" * 32))

    def test_changed_ciphertext_fails(self):
        box = encrypt_for(self.key.public_key(), b"data", self.context)
        box["ct"] = ("0" if box["ct"][0] != "0" else "1") + box["ct"][1:]
        with self.assertRaises(DecryptionError):
            decrypt_with(self.key, box, self.context)

    def test_plain_text_is_not_encrypted(self):
        self.assertFalse(is_encrypted("hello"))
        with self.assertRaises(DecryptionError):
            decrypt_content("hello", self.key, self.context)


# Encryption keys in the identity and the trusted list.
class TestEncryptionKeys(unittest.TestCase):

    def setUp(self):
        self.keys_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.keys_dir, ignore_errors=True)

    def test_new_peers_get_encryption_keys(self):
        generate_keys(["A"], self.keys_dir)
        self.assertIsNotNone(load_identity("A", self.keys_dir).encryption_key)
        load_trust_store(self.keys_dir).encryption_key("A")

    def test_step4_key_file_is_upgraded(self):
        # A key folder made in Step 4: signing key only, old list format.
        signing = Ed25519PrivateKey.generate()
        with open(os.path.join(self.keys_dir, "A.key"), "w", encoding="utf-8") as file:
            file.write(signing.private_bytes_raw().hex())
        with open(os.path.join(self.keys_dir, TRUST_FILE), "w", encoding="utf-8") as file:
            json.dump({"A": signing.public_key().public_bytes_raw().hex()}, file)

        self.assertEqual(generate_keys(["A"], self.keys_dir), {"A": "upgraded"})

        identity = load_identity("A", self.keys_dir)
        self.assertIsNotNone(identity.encryption_key)

        # The signing key is unchanged, so the peer keeps its identity.
        self.assertEqual(identity.private_key.private_bytes_raw(), signing.private_bytes_raw())
        load_trust_store(self.keys_dir).encryption_key("A")

    def test_old_trusted_list_still_checks_signatures(self):
        signing = Ed25519PrivateKey.generate()
        store = TrustStore({"A": signing.public_key().public_bytes_raw().hex()})
        store.verify("A", b"x", signing.sign(b"x").hex())

        with self.assertRaises(AuthenticationError):
            store.encryption_key("A")


# Encrypted file transfers (no peers needed).
class TestEncryptedFiles(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.keys_dir = os.path.join(self.work_dir, "keys")
        generate_keys(["A", "C"], self.keys_dir)
        self.a = load_identity("A", self.keys_dir)
        self.c = load_identity("C", self.keys_dir)
        self.trust = load_trust_store(self.keys_dir)

        self.file_path = os.path.join(self.work_dir, "secret.txt")
        with open(self.file_path, "wb") as file:
            file.write(b"top secret file content\n")

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    # Record exactly what send_file() puts on the wire.
    def capture(self, **options):
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
            send_file("127.0.0.1", server.getsockname()[1], self.file_path, **options)
            thread.join(5)
        return captured[0]

    # Play recorded bytes into receive_file() as peer A.
    def deliver(self, wire, decryption_key):
        receiver, sender = socket.socketpair()
        with receiver, sender:
            sender.sendall(wire)
            sender.shutdown(socket.SHUT_WR)
            return receive_file(receiver, os.path.join(self.work_dir, "in"),
                                ReplayGuard(), self.trust, decryption_key)

    def test_file_content_not_visible_on_the_wire(self):
        wire = self.capture(identity=self.c, recipient_key=self.trust.encryption_key("A"))
        self.assertNotIn(b"top secret", wire)

    def test_encrypted_file_arrives_intact(self):
        wire = self.capture(identity=self.c, recipient_key=self.trust.encryption_key("A"))
        result = self.deliver(wire, self.a.encryption_key)

        self.assertEqual(result["status"], "verified")
        with open(os.path.join(self.work_dir, "in", "secret.txt"), "rb") as file:
            self.assertEqual(file.read(), b"top secret file content\n")

    def test_file_for_another_peer_cannot_be_decrypted(self):
        wire = self.capture(identity=self.c, recipient_key=self.trust.encryption_key("C"))
        with self.assertRaises(DecryptionError):
            self.deliver(wire, self.a.encryption_key)

    def test_changed_ciphertext_rejected(self):
        wire = bytearray(self.capture(identity=self.c,
                                      recipient_key=self.trust.encryption_key("A")))
        wire[-5] ^= 0x01
        with self.assertRaises(DecryptionError):
            self.deliver(bytes(wire), self.a.encryption_key)

    def test_plain_file_refused_by_peer(self):
        wire = self.capture(identity=self.c)
        with self.assertRaises(ValueError):
            self.deliver(wire, self.a.encryption_key)


# Real bootstrap server and peers A - B - C.
class TestLiveEncryption(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp()
        cls.keys_dir = os.path.join(cls.work_dir, "keys")
        cls.shared = os.path.join(cls.work_dir, "shared")
        os.makedirs(cls.shared)
        with open(os.path.join(cls.shared, "report.txt"), "wb") as file:
            file.write(b"confidential report\n")

        generate_keys(["A", "B", "C"], cls.keys_dir)
        cls.trust = load_trust_store(cls.keys_dir)
        cls.id_a = load_identity("A", cls.keys_dir)

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
                shared_folder=cls.shared,
                received_folder=os.path.join(cls.work_dir, "recv", peer_id),
                verbose=False, keys_dir=cls.keys_dir,
            ).start()

        # Record what Peer B (the middle peer) receives.
        cls.seen_by_b = []
        peer_b = cls.peers["B"]
        original = peer_b.receive_routed_message

        def spy(connection):
            fields = original(connection)
            cls.seen_by_b.append(fields[2])
            return fields

        peer_b.receive_routed_message = spy
        cls.address_a = ("127.0.0.1", cls.peers["A"].port)

    @classmethod
    def tearDownClass(cls):
        for peer in cls.peers.values():
            peer.stop()
        cls.bootstrap.stop()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    # A message to C with a valid HMAC and A's signature.
    def raw_message(self, content):
        freshness = new_freshness()
        route = ["A", "B", "C"]
        original = canonical_routed_message("A", "C", content, route, freshness)
        return encode_secure_routed_message(
            "A", "C", content, route, calculate_hmac(original, KEY), freshness,
            self.id_a.sign(original),
        ), freshness

    def test_message_delivered_and_middle_peer_sees_only_ciphertext(self):
        before = len(self.seen_by_b)
        result = send_routed_message(
            "A", "C", SECRET, bootstrap_address=self.bootstrap_address,
            verbose=False, keys_dir=self.keys_dir,
        )

        self.assertEqual(result["status"], "ok")
        seen = self.seen_by_b[before:]
        self.assertTrue(seen)
        for content in seen:
            self.assertTrue(is_encrypted(content))
            self.assertNotIn("door code", content)

    def test_plain_text_message_refused(self):
        line, _ = self.raw_message("not encrypted")
        self.assertEqual(send_raw(self.address_a, line), b"")

    def test_message_encrypted_for_wrong_peer_refused(self):
        # Encrypted for B instead of the destination C.
        freshness = new_freshness()
        content = encrypt_content(SECRET, self.trust.encryption_key("B"),
                                  message_context("A", "C", freshness["msg_id"]))
        route = ["A", "B", "C"]
        original = canonical_routed_message("A", "C", content, route, freshness)
        line = encode_secure_routed_message(
            "A", "C", content, route, calculate_hmac(original, KEY), freshness,
            self.id_a.sign(original),
        )
        self.assertEqual(send_raw(self.address_a, line), b"")

    def test_encrypted_file_request(self):
        request_file("report.txt", requester="A", owner="C",
                     bootstrap_address=self.bootstrap_address, verbose=False,
                     keys_dir=self.keys_dir)

        received = os.path.join(self.work_dir, "recv", "A", "report.txt")
        content = b""
        for _ in range(50):
            if os.path.isfile(received):
                with open(received, "rb") as file:
                    content = file.read()
                if content == b"confidential report\n":
                    break
            time.sleep(0.1)

        self.assertEqual(content, b"confidential report\n")


if __name__ == "__main__":
    unittest.main()
