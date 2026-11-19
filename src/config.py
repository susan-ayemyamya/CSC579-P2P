"""
Susan I modified some of your file for project advancement
Shared configuration for all peers and the bootstrap server.

"""

import os

#Read an integer environment variable
def _env_int(name, default):

    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer")

# Read a dacimal environment variable
def _env_float(name, default):

    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    try:
        return float(value)
    except ValueError:
        raise ValueError(f"{name} must be a number")


# Address this machine listens on (use 0.0.0.0 for cross-machine tests).
BIND_HOST = os.getenv("P2P_BIND_HOST", "127.0.0.1")

# Address other peers should use to reach this machine.
ADVERTISED_HOST = os.getenv("P2P_ADVERTISED_HOST", BIND_HOST)

# Bootstrap server location.
BOOTSTRAP_BIND = os.getenv("P2P_BOOTSTRAP_BIND", "127.0.0.1")
BOOTSTRAP_HOST = os.getenv("P2P_BOOTSTRAP_HOST", "127.0.0.1")
BOOTSTRAP_PORT = _env_int("P2P_BOOTSTRAP_PORT", 6000)

# Demonstration key: all peers use the same key for now.
SECRET_KEY = os.getenv(
    "P2P_SECRET_KEY",
    "demo-shared-key-change-later",
).encode("utf-8")

# Message limits and socket behaviour.
MAX_MESSAGE_SIZE = 4096

# Peer lists from the bootstrap server grow with the overlay (about
# 30 peers already fill 4096 bytes), so they get a larger limit.
MAX_DIRECTORY_SIZE = _env_int("P2P_MAX_DIRECTORY_SIZE", 64 * 1024)

# blocks the peer forever
SOCKET_TIMEOUT = _env_float("P2P_SOCKET_TIMEOUT", 5.0)

# Replay protection: a message older or newer than this many seconds is
# rejected. Peer clocks must be roughly correct (automatic time is enough).
REPLAY_WINDOW = _env_float("P2P_REPLAY_WINDOW", 30.0)

# Peer authentication: folder with each peer's private key and the list
# of trusted public keys (created with: python -m src.identity setup).
KEYS_DIR = os.getenv("P2P_KEYS_DIR", "keys")

# Security monitor: every peer starts with trust 1.0; each bad event
# lowers it. A peer below TRUST_THRESHOLD is quarantined. Old events
# count less over time: a penalty is multiplied by TRUST_DECAY once per
# DECAY_PERIOD seconds.
TRUST_THRESHOLD = _env_float("P2P_TRUST_THRESHOLD", 0.6)
TRUST_DECAY = _env_float("P2P_TRUST_DECAY", 0.9)
DECAY_PERIOD = _env_float("P2P_DECAY_PERIOD", 10.0)

# How much each kind of bad event lowers the trust score.
PENALTIES = {
    "bad_hmac": 0.2,
    "bad_signature": 0.3,
    "replay": 0.3,
    "bad_encryption": 0.2,
    "malformed": 0.1,
    "flood": 0.3,
    "unauthorized_join": 0.5,
}

# Flood detection: messages per second from one source above
# mean + 3 standard deviations of its normal rate (and at least
# FLOOD_MIN_RATE) count as a flood.
FLOOD_MIN_RATE = _env_int("P2P_FLOOD_MIN_RATE", 20)

# Reports from peers needed before the bootstrap server marks a peer as
# quarantined for the whole overlay.
REPORTS_TO_QUARANTINE = _env_int("P2P_REPORTS_TO_QUARANTINE", 1)

# Folder for the security alert logs.
ALERTS_DIR = os.getenv("P2P_ALERTS_DIR", "alerts")

# Default ports for the original three-peer demonstration.
DEFAULT_PEER_PORTS = {
    "Peer A": 5000,
    "Peer B": 5001,
    "Peer C": 5002,
}

# File-transfer server port = peer port + this offset.
FILE_PORT_OFFSET = 100

# Default overlay links for the original three-peer demonstration.
DEFAULT_NEIGHBOURS = {
    "Peer A": ["Peer B"],
    "Peer B": ["Peer A", "Peer C"],
    "Peer C": ["Peer B"],
}
