"""
New file: per-peer identity (peer authentication).

Each peer has its own Ed25519 key pair:
  - the private key stays with that peer only (keys/<Peer_ID>.key)
  - the public key is listed in keys/trusted_peers.json, which every
    peer and the bootstrap server use to check signatures

A peer signs what it sends. Because nobody else has its private key,
no other peer can create a valid signature in its name. Only peers in
the trusted list can join the overlay.

Create the keys once with:
    python -m src.identity setup
For cross-machine tests, copy the keys folder to the other machine.
"""

import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src import config

TRUST_FILE = "trusted_peers.json"
SIGNATURE_LENGTH = 128  # 64 bytes as hex
DEFAULT_PEERS = ["Peer A", "Peer B", "Peer C"]


# Raised when a peer is unknown or its signature is wrong.
class AuthenticationError(ValueError):
    pass


# File name of a peer's private key, e.g. "Peer A" -> "Peer_A.key".
def _key_file(peer_id):
    return peer_id.replace(" ", "_") + ".key"


# Create key pairs for the given peers and add their public keys to the
# trusted list. Existing keys are kept, so running it again is safe.
#   1. Load the current trusted list (if any).
#   2. For each peer without a private key file, create a new key pair.
#   3. Save the private key file and add the public key to the list.
#   4. Write the trusted list back to disk.
def generate_keys(peer_ids, keys_dir=None):
    keys_dir = keys_dir or config.KEYS_DIR
    os.makedirs(keys_dir, exist_ok=True)

    trust_path = os.path.join(keys_dir, TRUST_FILE)
    trusted = {}

    if os.path.isfile(trust_path):
        with open(trust_path, encoding="utf-8") as file:
            trusted = json.load(file)

    created = []

    for peer_id in peer_ids:
        key_path = os.path.join(keys_dir, _key_file(peer_id))

        if os.path.isfile(key_path):
            private_key = load_identity(peer_id, keys_dir).private_key
        else:
            private_key = Ed25519PrivateKey.generate()
            with open(key_path, "w", encoding="utf-8") as file:
                file.write(private_key.private_bytes_raw().hex())
            created.append(peer_id)

        trusted[peer_id] = private_key.public_key().public_bytes_raw().hex()

    with open(trust_path, "w", encoding="utf-8") as file:
        json.dump(trusted, file, indent=2, sort_keys=True)

    return created


# The identity of one peer: its ID and its private key.
class Identity:

    def __init__(self, peer_id, private_key):
        self.peer_id = peer_id
        self.private_key = private_key

    # Sign some bytes and return the signature as hex.
    def sign(self, data):
        return self.private_key.sign(data).hex()


# Load one peer's private key from the keys folder.
def load_identity(peer_id, keys_dir=None):
    keys_dir = keys_dir or config.KEYS_DIR
    key_path = os.path.join(keys_dir, _key_file(peer_id))

    if not os.path.isfile(key_path):
        raise AuthenticationError(
            f"No private key for {peer_id} in '{keys_dir}'. "
            f"Run: python -m src.identity setup \"{peer_id}\""
        )

    with open(key_path, encoding="utf-8") as file:
        raw = bytes.fromhex(file.read().strip())

    return Identity(peer_id, Ed25519PrivateKey.from_private_bytes(raw))


# The list of trusted peers and their public keys.
class TrustStore:

    def __init__(self, public_keys):
        self._keys = {
            peer_id: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
            for peer_id, key_hex in public_keys.items()
        }

    # Is this peer allowed in the overlay?
    def is_trusted(self, peer_id):
        return peer_id in self._keys

    # Check that 'signature' was made by peer_id's private key over 'data'.
    #   1. The peer must be in the trusted list.
    #   2. The signature must be 128 hex characters.
    #   3. It must verify with the peer's public key.
    # Raises AuthenticationError if any check fails.
    def verify(self, peer_id, data, signature):
        public_key = self._keys.get(peer_id)

        if public_key is None:
            raise AuthenticationError(f"Unknown peer: {peer_id}")

        if not isinstance(signature, str) or len(signature) != SIGNATURE_LENGTH:
            raise AuthenticationError(f"Missing or invalid signature from {peer_id}")

        try:
            public_key.verify(bytes.fromhex(signature), data)
        except (InvalidSignature, ValueError):
            raise AuthenticationError(f"Signature check failed: not sent by {peer_id}")

    # Peer IDs in the trusted list.
    def peers(self):
        return sorted(self._keys)


# Load the trusted list from the keys folder.
def load_trust_store(keys_dir=None):
    keys_dir = keys_dir or config.KEYS_DIR
    trust_path = os.path.join(keys_dir, TRUST_FILE)

    if not os.path.isfile(trust_path):
        raise AuthenticationError(
            f"No trusted peer list in '{keys_dir}'. Run: python -m src.identity setup"
        )

    with open(trust_path, encoding="utf-8") as file:
        return TrustStore(json.load(file))


# Bytes of a request that are signed: every field except the signature,
# in a fixed order so signer and checker build the same bytes.
def canonical_request(request):
    unsigned = {k: v for k, v in request.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Add a signature to a request (for example a registration).
def sign_request(request, identity):
    signed = dict(request)
    signed["signature"] = identity.sign(canonical_request(signed))
    return signed


# Check a signed request was made by the peer named in it.
def verify_request(request, trust_store):
    trust_store.verify(
        request.get("peer_id"),
        canonical_request(request),
        request.get("signature"),
    )


# Command line: create keys for peers and show the trusted list.
#   python -m src.identity setup                 (Peer A, B and C)
#   python -m src.identity setup "Peer D" ...    (other peers)
#   python -m src.identity list
def main(argv=None):
    args = sys.argv[1:] if argv is None else argv

    if args and args[0] == "setup":
        peer_ids = args[1:] or DEFAULT_PEERS
        created = generate_keys(peer_ids)
        print(f"Keys folder: {os.path.abspath(config.KEYS_DIR)}")
        for peer_id in peer_ids:
            state = "created" if peer_id in created else "already existed"
            print(f"  {peer_id}: {state}")

    elif args and args[0] == "list":
        store = load_trust_store()
        print("Trusted peers:")
        for peer_id in store.peers():
            print(f"  {peer_id}")

    else:
        print("Usage:")
        print("  python -m src.identity setup [peer IDs...]")
        print("  python -m src.identity list")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
