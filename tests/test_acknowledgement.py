
import json
import unittest

from src.message import (
    canonical_acknowledgement,
    encode_secure_acknowledgement,
    decode_secure_acknowledgement,
)
from src.security import calculate_hmac, verify_hmac


SECRET_KEY = b"demo-shared-key-change-later"


class TestAcknowledgement(unittest.TestCase):

    def test_canonical_acknowledgement(self):
        first = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        second = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        self.assertEqual(first, second)

        acknowledgement = json.loads(first.decode("utf-8"))

        self.assertEqual(acknowledgement["status"], "ok")
        self.assertEqual(acknowledgement["sender"], "Peer A")
        self.assertEqual(acknowledgement["destination"], "Peer C")

    def test_encode_and_decode_acknowledgement(self):
        original_bytes = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        tag = calculate_hmac(original_bytes, SECRET_KEY)

        encoded = encode_secure_acknowledgement(
            "ok", "Peer A", "Peer C", tag
        )

        decoded = decode_secure_acknowledgement(encoded[:-1])

        status, sender, destination, received_tag, received_bytes = decoded

        self.assertEqual(status, "ok")
        self.assertEqual(sender, "Peer A")
        self.assertEqual(destination, "Peer C")
        self.assertEqual(received_tag, tag)
        self.assertEqual(received_bytes, original_bytes)

    def test_valid_acknowledgement_hmac(self):
        original_bytes = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        tag = calculate_hmac(original_bytes, SECRET_KEY)

        self.assertTrue(
            verify_hmac(original_bytes, SECRET_KEY, tag)
        )

    def test_modified_destination_is_rejected(self):
        original_bytes = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        tag = calculate_hmac(original_bytes, SECRET_KEY)

        encoded = encode_secure_acknowledgement(
            "ok", "Peer A", "Peer C", tag
        )

        modified = json.loads(encoded.decode("utf-8"))
        modified["destination"] = "Peer B"

        modified_bytes = json.dumps(modified).encode("utf-8")

        (
            status,
            sender,
            destination,
            received_tag,
            received_bytes,
        ) = decode_secure_acknowledgement(
            modified_bytes
        )

        self.assertFalse(
            verify_hmac(received_bytes, SECRET_KEY, received_tag)
        )

    def test_wrong_key_is_rejected(self):
        original_bytes = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )
    def test_forged_acknowledgement_is_rejected(self):
        # Create a legitimate acknowledgement.
        original_bytes = canonical_acknowledgement(
            "ok", "Peer A", "Peer C"
        )

        tag = calculate_hmac(original_bytes, SECRET_KEY)

        encoded = encode_secure_acknowledgement(
            "ok", "Peer A", "Peer C", tag
        )

        # Modify the acknowledgement's authentication tag.
        forged = json.loads(encoded.decode("utf-8"))
        forged["tag"] = "0" * 64

        forged_bytes = json.dumps(forged).encode("utf-8")

        # Decode the forged acknowledgement.
        (
            status,
            sender,
            destination,
            received_tag,
            received_bytes,
        ) = decode_secure_acknowledgement(forged_bytes)

        # The forged acknowledgement must fail verification.
        self.assertFalse(
            verify_hmac(
                received_bytes,
                SECRET_KEY,
                received_tag,
            )
        )
        tag = calculate_hmac(original_bytes, SECRET_KEY)

        self.assertFalse(
            verify_hmac(
                original_bytes,
                b"incorrect-key",
                tag,
            )
        )

    def test_invalid_acknowledgement_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            canonical_acknowledgement(
                "", "Peer A", "Peer C"
            )


if __name__ == "__main__":
    unittest.main()
