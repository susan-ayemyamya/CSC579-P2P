"""
New file: replay protection.

Every signed message carries three freshness fields:
  msg_id     - a unique ID for the message (an ACK repeats the msg_id
               of the message it confirms)
  nonce      - a random value that is never used twice
  timestamp  - the sending time in milliseconds

ReplayGuard rejects a message whose nonce was already seen, or whose
timestamp is outside the allowed window (config.REPLAY_WINDOW).
The fields are part of the signed data, so they cannot be changed
without breaking the HMAC.
"""

import secrets
import threading
import time
import uuid
from collections import deque

from src import config

HEX_DIGITS = set("0123456789abcdef")
FIELD_LENGTH = 32


# Raised when a message is replayed, too old or from the future.
class ReplayError(ValueError):
    pass


# Current time in milliseconds.
def now_ms():
    return int(time.time() * 1000)


# Create the freshness fields for a new message.
# Pass msg_id to reuse the ID of the message an ACK confirms.
def new_freshness(msg_id=None):
    return {
        "msg_id": msg_id or uuid.uuid4().hex,
        "nonce": secrets.token_hex(16),
        "timestamp": now_ms(),
    }


# Check that a value is a 32-character lowercase hex string.
def _is_hex_id(value):
    return (
        isinstance(value, str)
        and len(value) == FIELD_LENGTH
        and set(value) <= HEX_DIGITS
    )


# Check the format of the freshness fields and return a clean copy.
def validate_freshness(freshness):
    if not isinstance(freshness, dict):
        raise ValueError("Freshness fields are missing")

    msg_id = freshness.get("msg_id")
    nonce = freshness.get("nonce")
    timestamp = freshness.get("timestamp")

    if not _is_hex_id(msg_id):
        raise ValueError("Invalid message ID")

    if not _is_hex_id(nonce):
        raise ValueError("Invalid nonce")

    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ValueError("Invalid timestamp")

    return {"msg_id": msg_id, "nonce": nonce, "timestamp": timestamp}


# Remembers recently seen nonces and rejects replayed or stale messages.
# One guard is used per peer; it is safe to call from several threads.
class ReplayGuard:

    def __init__(self, window=None, clock=now_ms):
        self.window_ms = int((config.REPLAY_WINDOW if window is None else window) * 1000)
        self._clock = clock
        self._seen = {}
        self._order = deque()
        self._lock = threading.Lock()

    # Accept a message once. Raise ReplayError if it is replayed,
    # too old or too far in the future.
    #   1. Check the format of the fields.
    #   2. Reject timestamps outside the allowed window.
    #   3. Forget nonces that are too old to matter any more.
    #   4. Reject a nonce that was already seen; otherwise remember it.
    def check(self, freshness):
        fields = validate_freshness(freshness)
        now = self._clock()
        age = now - fields["timestamp"]

        if age > self.window_ms:
            raise ReplayError("Message is too old (possible replay)")

        if age < -self.window_ms:
            raise ReplayError("Message timestamp is in the future")

        with self._lock:
            self._forget_old(now)

            if fields["nonce"] in self._seen:
                raise ReplayError("Replayed message (nonce already used)")

            self._seen[fields["nonce"]] = fields["timestamp"]
            self._order.append((fields["timestamp"], fields["nonce"]))

        return fields

    # Drop nonces older than the window. A replay of such a message is
    # already rejected by its old timestamp, so it no longer needs to be
    # remembered. This keeps memory use small.
    def _forget_old(self, now):
        limit = now - 2 * self.window_ms

        while self._order and self._order[0][0] < limit:
            _, nonce = self._order.popleft()
            self._seen.pop(nonce, None)

    # Number of nonces currently remembered (used by tests).
    def __len__(self):
        with self._lock:
            return len(self._seen)
