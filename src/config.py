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

# blocks the peer forever
SOCKET_TIMEOUT = _env_float("P2P_SOCKET_TIMEOUT", 5.0)

# Replay protection: a message older or newer than this many seconds is
# rejected. Peer clocks must be roughly correct (automatic time is enough).
REPLAY_WINDOW = _env_float("P2P_REPLAY_WINDOW", 30.0)

# Peer authentication: folder with each peer's private key and the list
# of trusted public keys (created with: python -m src.identity setup).
KEYS_DIR = os.getenv("P2P_KEYS_DIR", "keys")

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
