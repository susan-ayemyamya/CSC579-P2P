
import unittest

from src.message import (
    canonical_routed_message,
    encode_secure_routed_message,
    decode_secure_routed_message,
)
from src.security import calculate_hmac, verify_hmac


class TestRoutedMessage(unittest.TestCase):

    def setUp(self):
        self.sender = "Peer A"
        self.destination = "Peer C"
        self.content = "Hello from Peer A"
        self.route = ["Peer A", "Peer B", "Peer C"]
        self.secret_key = b"demo-shared-key-change-later"

        self.original_bytes = canonical_routed_message(
            self.sender,
            self.destination,
            self.content,
            self.route,
        )

        self.tag = calculate_hmac(
            self.original_bytes,
            self.secret_key,
        )

    def test_canonical_routed_message(self):
        self.assertIsInstance(self.original_bytes, bytes)

    def test_encode_and_decode_routed_message(self):
        encoded = encode_secure_routed_message(
            self.sender,
            self.destination,
            self.content,
            self.route,
            self.tag,
        )

        result = decode_secure_routed_message(encoded[:-1])

        sender, destination, content, route, tag, original_bytes = result

        self.assertEqual(sender, self.sender)
        self.assertEqual(destination, self.destination)
        self.assertEqual(content, self.content)
        self.assertEqual(route, self.route)
        self.assertEqual(tag, self.tag)
        self.assertEqual(original_bytes, self.original_bytes)

    def test_valid_routed_message_hmac(self):
        self.assertTrue(
            verify_hmac(
                self.original_bytes,
                self.secret_key,
                self.tag,
            )
        )

    def test_modified_destination_rejected(self):
        modified_bytes = canonical_routed_message(
            self.sender,
            "Peer D",
            self.content,
            ["Peer A", "Peer B", "Peer D"],
        )

        self.assertFalse(
            verify_hmac(
                modified_bytes,
                self.secret_key,
                self.tag,
            )
        )

    def test_invalid_route_rejected(self):
        with self.assertRaises(ValueError):
            canonical_routed_message(
                "Peer A",
                "Peer C",
                "Hello",
                ["Peer B", "Peer C"],
            )

    def test_repeated_peer_rejected(self):
        with self.assertRaises(ValueError):
            canonical_routed_message(
                "Peer A",
                "Peer C",
                "Hello",
                ["Peer A", "Peer B", "Peer A", "Peer C"],
            )


if __name__ == "__main__":
    unittest.main()
