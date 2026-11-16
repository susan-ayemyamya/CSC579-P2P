"""
New file: tests for end-to-end encryption.

Checks the encryption functions on their own and the encryption keys,
including the upgrade of key folders made in Step 4.
"""

import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.encryption import (
    DecryptionError,
    decrypt_content,
    decrypt_with,
    encrypt_content,
    encrypt_for,
    is_encrypted,
    message_context,
)
from src.identity import (
    TRUST_FILE,
    AuthenticationError,
    TrustStore,
    generate_keys,
    load_identity,
    load_trust_store,
)

SECRET = "meet at 10, door code 4321"


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


if __name__ == "__main__":
    unittest.main()
