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