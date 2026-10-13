import json


def encode_message(sender, content):
    """Convert a message into UTF-8 JSON bytes."""

    message = {
        "sender": sender,
        "content": content,
    }

    return json.dumps(message).encode("utf-8")


def decode_message(data):
    """Convert UTF-8 JSON bytes back into a message."""

    message = json.loads(data.decode("utf-8"))

    if not isinstance(message, dict):
        raise ValueError("Message must be a JSON object")

    if not isinstance(message.get("sender"), str):
        raise ValueError("Message sender must be a string")

    if not isinstance(message.get("content"), str):
        raise ValueError("Message content must be a string")

    return message
def canonical_message(sender, content):
    """Create consistent bytes for HMAC verification."""
    return json.dumps(
        {"sender": sender, "content": content},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_secure_message(sender, content, tag):
    """Package a message and its HMAC tag as one JSON line."""
    envelope = {
        "sender": sender,
        "content": content,
        "tag": tag,
    }
    return json.dumps(envelope).encode("utf-8") + b"\n"


def decode_secure_message(data):
    """Parse a message and return its contents and verification data."""
    envelope = json.loads(data.decode("utf-8"))

    if not isinstance(envelope, dict):
        raise ValueError("Message must be a JSON object")

    sender = envelope.get("sender")
    content = envelope.get("content")
    tag = envelope.get("tag")

    if not all(isinstance(value, str) for value in (sender, content, tag)):
        raise ValueError("Sender, content, and tag must be strings")

    if len(tag) != 64:
        raise ValueError("Invalid HMAC tag length")

    original_bytes = canonical_message(sender, content)
    return sender, content, tag, original_bytes