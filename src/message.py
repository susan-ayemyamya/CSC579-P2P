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


def canonical_routed_message(sender, destination, content, route):
    """Create consistent bytes for authenticating a routed message."""

    if not isinstance(sender, str) or not sender.strip():
        raise ValueError("Sender must be a non-empty string")

    if not isinstance(destination, str) or not destination.strip():
        raise ValueError("Destination must be a non-empty string")

    if not isinstance(content, str):
        raise ValueError("Content must be a string")

    if not isinstance(route, list) or len(route) < 2:
        raise ValueError("Route must contain at least two peers")

    if not all(
        isinstance(peer, str) and peer.strip()
        for peer in route
    ):
        raise ValueError("Route must contain valid peer IDs")

    if len(set(route)) != len(route):
        raise ValueError("Route must not contain repeated peers")

    if route[0] != sender:
        raise ValueError("Route must start with the sender")

    if route[-1] != destination:
        raise ValueError("Route must end with the destination")

    message = {
        "sender": sender,
        "destination": destination,
        "content": content,
        "route": route,
    }

    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_secure_routed_message(
    sender, destination, content, route, tag
):
    """Package a routed message and its HMAC tag as one JSON line."""

    original_bytes = canonical_routed_message(
        sender, destination, content, route
    )

    if not isinstance(tag, str) or len(tag) != 64:
        raise ValueError("Invalid HMAC tag")

    envelope = json.loads(original_bytes.decode("utf-8"))
    envelope["tag"] = tag

    return json.dumps(envelope).encode("utf-8") + b"\n"


def decode_secure_routed_message(data):
    """Decode and validate a secure routed message."""

    envelope = json.loads(data.decode("utf-8"))

    if not isinstance(envelope, dict):
        raise ValueError("Message must be a JSON object")

    sender = envelope.get("sender")
    destination = envelope.get("destination")
    content = envelope.get("content")
    route = envelope.get("route")
    tag = envelope.get("tag")

    if not isinstance(tag, str) or len(tag) != 64:
        raise ValueError("Invalid HMAC tag")

    original_bytes = canonical_routed_message(
        sender, destination, content, route
    )

    return sender, destination, content, route, tag, original_bytes


def canonical_acknowledgement(status, sender, destination):
    """Create consistent bytes for authenticating a delivery acknowledgement."""

    if not isinstance(status, str) or not status.strip():
        raise ValueError("Status must be a non-empty string")

    if not isinstance(sender, str) or not sender.strip():
        raise ValueError("Sender must be a non-empty string")

    if not isinstance(destination, str) or not destination.strip():
        raise ValueError("Destination must be a non-empty string")

    acknowledgement = {
        "status": status,
        "sender": sender,
        "destination": destination,
    }

    return json.dumps(
        acknowledgement,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_secure_acknowledgement(
    status, sender, destination, tag
):
    """Package an acknowledgement and its HMAC tag."""

    original_bytes = canonical_acknowledgement(
        status, sender, destination
    )

    if not isinstance(tag, str) or len(tag) != 64:
        raise ValueError("Invalid HMAC tag")

    acknowledgement = json.loads(
        original_bytes.decode("utf-8")
    )

    acknowledgement["tag"] = tag

    return json.dumps(acknowledgement).encode("utf-8") + b"\n"


def decode_secure_acknowledgement(data):
    """Decode a secure acknowledgement and return its verification data."""

    acknowledgement = json.loads(data.decode("utf-8"))

    if not isinstance(acknowledgement, dict):
        raise ValueError("Acknowledgement must be a JSON object")

    status = acknowledgement.get("status")
    sender = acknowledgement.get("sender")
    destination = acknowledgement.get("destination")
    tag = acknowledgement.get("tag")

    if not isinstance(tag, str) or len(tag) != 64:
        raise ValueError("Invalid HMAC tag")

    original_bytes = canonical_acknowledgement(
        status, sender, destination
    )

    return status, sender, destination, tag, original_bytes
