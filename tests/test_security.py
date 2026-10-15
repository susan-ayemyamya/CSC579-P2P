
import unittest

from src.message import canonical_message
from src.security import calculate_hmac, verify_hmac


SECRET_KEY = b"demo-shared-key-change-later"


class TestMessageSecurity(unittest.TestCase):

    def test_valid_message_is_accepted(self):
        message = canonical_message(
            "Peer B",
            "Hello from Peer B!",
        )
        tag = calculate_hmac(message, SECRET_KEY)

        self.assertTrue(
            verify_hmac(message, SECRET_KEY, tag)
        )

    def test_modified_message_is_rejected(self):
        # Create the original message and its HMAC tag.
        original_message = canonical_message(
            "Peer B",
            "Transfer approved",
        )
        original_tag = calculate_hmac(
            original_message,
            SECRET_KEY,
        )

        # Change the content but keep the original tag.
        modified_message = canonical_message(
            "Peer B",
            "Transfer rejected",
        )

        # The modified message must fail verification.
        self.assertFalse(
            verify_hmac(
                modified_message,
                SECRET_KEY,
                original_tag,
            )
        )

    def test_wrong_key_is_rejected(self):
        message = canonical_message(
            "Peer B",
            "Hello from Peer B!",
        )
        tag = calculate_hmac(message, SECRET_KEY)

        # Verify using an incorrect key.
        self.assertFalse(
            verify_hmac(
                message,
                b"incorrect-key",
                tag,
            )
        )


if __name__ == "__main__":
    unittest.main()
