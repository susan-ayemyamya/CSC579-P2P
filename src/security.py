import hashlib
import hmac


def calculate_hmac(message, secret_key):
    """Calculate a message authentication code."""

    return hmac.new(
        secret_key,
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(message, secret_key, received_tag):
    """Check whether a message authentication code is valid."""

    expected_tag = calculate_hmac(message, secret_key)

    return hmac.compare_digest(expected_tag, received_tag)