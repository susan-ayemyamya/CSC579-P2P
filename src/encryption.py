"""
New file: end-to-end encryption (confidentiality).

The sender encrypts for one recipient using that recipient's public
X25519 key from the trusted list:
  1. create a new one-time X25519 key pair (ephemeral key)
  2. combine it with the recipient's public key (X25519 key agreement)
     to get a shared secret that only the sender and the recipient can
     compute
  3. turn the secret into an AES-256 key (HKDF-SHA256)
  4. encrypt with AES-256-GCM, which also detects any change

The 'context' (who sends, who receives, which message) is bound to the
ciphertext, so it cannot be moved into a different message. Peers in
the middle of a route only ever see the ciphertext.
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHM = "X25519-AES256GCM"
HKDF_INFO = b"csc579-p2p end-to-end encryption"
NONCE_SIZE = 12


# Raised when data cannot be decrypted (wrong key, changed data or context).
class DecryptionError(ValueError):
    pass


# Derive the AES key from the X25519 shared secret.
def _derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)


# Encrypt bytes for one recipient. Returns (header, ciphertext): the
# header (algorithm, ephemeral public key, nonce) is sent with the data.
#   1. Create a one-time key pair.
#   2. Agree a shared secret with the recipient's public key.
#   3. Derive the AES key and encrypt with a random nonce.
def encrypt_bytes_for(recipient_public_key, plaintext, context):
    ephemeral = X25519PrivateKey.generate()
    key = _derive_key(ephemeral.exchange(recipient_public_key))
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, context)

    header = {
        "alg": ALGORITHM,
        "eph": ephemeral.public_key().public_bytes_raw().hex(),
        "nonce": nonce.hex(),
    }
    return header, ciphertext


# Decrypt bytes made by encrypt_bytes_for(), using the recipient's key.
#   1. Check the header has the expected fields.
#   2. Rebuild the same shared secret from the ephemeral public key.
#   3. Decrypt; AES-GCM fails if the data or the context was changed.
def decrypt_bytes_with(private_key, header, ciphertext, context):
    if not isinstance(header, dict) or header.get("alg") != ALGORITHM:
        raise DecryptionError("Not encrypted with the expected algorithm")

    try:
        ephemeral = X25519PublicKey.from_public_bytes(bytes.fromhex(header["eph"]))
        nonce = bytes.fromhex(header["nonce"])
    except (KeyError, TypeError, ValueError):
        raise DecryptionError("Badly formed encryption header")

    if len(nonce) != NONCE_SIZE:
        raise DecryptionError("Badly formed encryption header")

    try:
        key = _derive_key(private_key.exchange(ephemeral))
        return AESGCM(key).decrypt(nonce, ciphertext, context)
    except (InvalidTag, ValueError):
        raise DecryptionError("Decryption failed: wrong key or changed data")


# Encrypt bytes into one JSON-friendly box (header + ciphertext as hex).
def encrypt_for(recipient_public_key, plaintext, context):
    header, ciphertext = encrypt_bytes_for(recipient_public_key, plaintext, context)
    return {**header, "ct": ciphertext.hex()}


# Decrypt a box made by encrypt_for().
def decrypt_with(private_key, box, context):
    if not isinstance(box, dict):
        raise DecryptionError("Not an encrypted box")

    try:
        ciphertext = bytes.fromhex(box["ct"])
    except (KeyError, TypeError, ValueError):
        raise DecryptionError("Badly formed encrypted box")

    return decrypt_bytes_with(private_key, box, ciphertext, context)


# Context that ties an encrypted file to its transfer ID.
def file_context(msg_id):
    return f"file|{msg_id}".encode("utf-8")


# Context that ties an encrypted message to its sender, destination and ID.
def message_context(sender, destination, msg_id):
    return f"msg|{sender}|{destination}|{msg_id}".encode("utf-8")


# Encrypt a text message and return it as a JSON string (the new content).
def encrypt_content(text, recipient_public_key, context):
    box = encrypt_for(recipient_public_key, text.encode("utf-8"), context)
    return json.dumps(box, sort_keys=True, separators=(",", ":"))


# Is this message content an encrypted box?
def is_encrypted(content):
    try:
        box = json.loads(content)
    except (TypeError, ValueError):
        return False

    return isinstance(box, dict) and box.get("alg") == ALGORITHM


# Decrypt message content made by encrypt_content() back to text.
def decrypt_content(content, private_key, context):
    if not is_encrypted(content):
        raise DecryptionError("Message content is not encrypted")

    return decrypt_with(private_key, json.loads(content), context).decode("utf-8")
