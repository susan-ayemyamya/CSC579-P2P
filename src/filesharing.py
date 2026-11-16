'''
Modifications (branch overlay-improvements)
   1. SECRET_KEY now comes from src/config.py instead of a local copy.
      Why: the key was copied in four files. Keeping it in one place
      means Step 4 (per-peer keys) only has to change config.py.

   2. (branch replay-protection) send_file() adds signed freshness fields (msg_id, nonce, timestamp)
      to the file metadata, and receive_file() checks them when a
      replay_guard is given (peers always pass one).
      Why: a captured file transfer could otherwise be sent again.

   3. (branch peer-authentication) send_file() can sign the metadata
      with the sending peer's private key (identity), and receive_file()
      checks that signature when a trust_store is given (peers always
      pass one).
      Why: the receiver can be sure which peer really sent the file.

   4. (branch encryption) send_file() can encrypt the file for the
      receiving peer (recipient_key); receive_file() decrypts it when a
      decryption_key is given (peers always encrypt and decrypt).
      Why: before, the file content travelled as plain bytes that
      anyone watching the network could read.

Everything else in this file is unchanged.

'''

import os
import hashlib
import json
import socket

from src.security import calculate_hmac, verify_hmac
from src.replay import new_freshness
from src.encryption import decrypt_bytes_with, encrypt_bytes_for, file_context
from src import config

CHUNK_SIZE = 4096
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
SECRET_KEY = config.SECRET_KEY

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_metadata(file_path):
    """Return basic information about a file."""

    if not os.path.isfile(file_path):
        raise FileNotFoundError("File does not exist")

    metadata = {
        "filename": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
        "sha256": calculate_file_hash(file_path),
    }

    return metadata

def receive_file_data(stream, file_size, destination_path):
    """Receive file data in chunks and save it to disk."""

    if not isinstance(file_size, int) or isinstance(file_size, bool):
        raise ValueError("Invalid file size")

    if file_size < 0 or file_size > MAX_FILE_SIZE:
        raise ValueError("File size is outside the permitted range")

    received = 0

    with open(destination_path, "wb") as output_file:

        while received < file_size:
            chunk = stream.read(
                min(CHUNK_SIZE, file_size - received)
            )

            if not chunk:
                raise ConnectionError("File transfer interrupted")

            output_file.write(chunk)
            received += len(chunk)

    return received


def receive_file(connection, destination_folder, replay_guard=None,
                 trust_store=None, decryption_key=None):
    """Receive a file and verify its HMAC and SHA-256 hash."""

    with connection.makefile("rb") as stream:

        metadata_line = stream.readline(4097)

        if (
            not metadata_line
            or len(metadata_line) > 4096
            or not metadata_line.endswith(b"\n")
        ):
            raise ValueError("Invalid file metadata")

        envelope = json.loads(metadata_line.decode("utf-8"))

        if not isinstance(envelope, dict):
            raise ValueError("Metadata envelope must be a JSON object")

        metadata = envelope.get("metadata")
        received_tag = envelope.get("tag")

        if not isinstance(metadata, dict):
            raise ValueError("Invalid metadata")

        if (
            not isinstance(received_tag, str)
            or len(received_tag) != 64
            or any(c not in "0123456789abcdef" for c in received_tag)
        ):
            raise ValueError("Invalid HMAC tag")

        # Recreate canonical metadata bytes.
        original_bytes = canonical_file_metadata(metadata)

        # Verify metadata authentication.
        if not verify_hmac(
            original_bytes,
            SECRET_KEY,
            received_tag
        ):
            raise ValueError("File metadata authentication failed")

        # Reject a replayed or stale file transfer. Peers pass their
        # replay guard; the signed metadata carries the freshness fields.
        if replay_guard is not None:
            replay_guard.check(metadata.get("freshness"))

        # Check which peer really sent the file (its signature).
        if trust_store is not None:
            trust_store.verify(
                metadata.get("sender"),
                original_bytes,
                envelope.get("signature"),
            )

        # Extract metadata only after successful authentication.
        filename = metadata.get("filename")
        file_size = metadata.get("file_size")
        expected_hash = metadata.get("sha256")

        if (
            not isinstance(filename, str)
            or not filename
            or filename in (".", "..")
            or os.path.basename(filename) != filename
            or "/" in filename
            or "\\" in filename
        ):
            raise ValueError("Invalid filename")

        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(c not in "0123456789abcdef" for c in expected_hash)
        ):
            raise ValueError("Invalid SHA-256 hash")

        if (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or file_size < 0
            or file_size > MAX_FILE_SIZE
        ):
            raise ValueError("File size is outside the permitted range")

        os.makedirs(destination_folder, exist_ok=True)

        destination_path = os.path.join(
            destination_folder,
            filename
        )

        try:
            # Encrypted transfer: read the ciphertext, decrypt it with this
            # peer's private key, then save the plain file.
            if decryption_key is not None:
                received_size = receive_encrypted_file_data(
                    stream, metadata, decryption_key, destination_path
                )
            else:
                received_size = receive_file_data(
                    stream,
                    file_size,
                    destination_path
                )

            actual_hash = calculate_file_hash(destination_path)

            if actual_hash != expected_hash:
                raise ValueError(
                    "File integrity verification failed"
                )

        except Exception:
            if os.path.exists(destination_path):
                os.remove(destination_path)
            raise

    return {
        "filename": filename,
        "file_size": received_size,
        "sha256": actual_hash,
        "status": "verified",
    }

# Read an encrypted file body, decrypt it and save the plain file.
#   1. The metadata must say the file is encrypted (plain files refused).
#   2. Read exactly 'cipher_size' bytes of ciphertext.
#   3. Decrypt with this peer's private key; any change makes it fail.
#   4. The plain size must match 'file_size'; then write it to disk.
def receive_encrypted_file_data(stream, metadata, decryption_key, destination_path):
    header = metadata.get("encryption")
    cipher_size = metadata.get("cipher_size")
    file_size = metadata.get("file_size")

    if not isinstance(header, dict):
        raise ValueError("File is not encrypted")

    if (
        not isinstance(cipher_size, int)
        or isinstance(cipher_size, bool)
        or cipher_size < 16
        or cipher_size > MAX_FILE_SIZE + 16
    ):
        raise ValueError("Invalid encrypted file size")

    ciphertext = stream.read(cipher_size)

    if len(ciphertext) != cipher_size:
        raise ConnectionError("File transfer interrupted")

    msg_id = (metadata.get("freshness") or {}).get("msg_id", "")
    plaintext = decrypt_bytes_with(
        decryption_key, header, ciphertext, file_context(msg_id)
    )

    if len(plaintext) != file_size:
        raise ValueError("Decrypted file size does not match")

    with open(destination_path, "wb") as output_file:
        output_file.write(plaintext)

    return len(plaintext)


def send_file(host, port, file_path, identity=None, recipient_key=None):
    """Send a file with HMAC-authenticated metadata."""

    metadata = get_file_metadata(file_path)

    if metadata["file_size"] > MAX_FILE_SIZE:
        raise ValueError("File size exceeds the 10 MB limit")

    # Add msg_id, nonce and timestamp so the transfer cannot be replayed.
    metadata["freshness"] = new_freshness()

    # Name the sending peer; it is covered by the signature below.
    if identity is not None:
        metadata["sender"] = identity.peer_id

    # Encrypt the file for the receiving peer. The encryption details are
    # part of the metadata, so they are covered by the HMAC and signature.
    ciphertext = None
    if recipient_key is not None:
        with open(file_path, "rb") as file:
            plaintext = file.read()

        header, ciphertext = encrypt_bytes_for(
            recipient_key, plaintext, file_context(metadata["freshness"]["msg_id"])
        )
        metadata["encryption"] = header
        metadata["cipher_size"] = len(ciphertext)

    # Create canonical metadata bytes.
    original_bytes = canonical_file_metadata(metadata)

    # Generate HMAC authentication tag.
    tag = calculate_hmac(original_bytes, SECRET_KEY)

    # Package metadata and authentication tag.
    envelope = {
        "metadata": metadata,
        "tag": tag,
    }

    # The sending peer signs the metadata with its private key.
    if identity is not None:
        envelope["signature"] = identity.sign(original_bytes)

    with socket.create_connection(
        (host, port),
        timeout=10
    ) as connection:

        # Send metadata envelope first.
        metadata_bytes = (
            json.dumps(envelope).encode("utf-8") + b"\n"
        )

        connection.sendall(metadata_bytes)

        # Encrypted transfer: send the ciphertext instead of the file.
        if ciphertext is not None:
            connection.sendall(ciphertext)
            return metadata

        # Send file contents in chunks.
        with open(file_path, "rb") as file:

            while True:
                chunk = file.read(CHUNK_SIZE)

                if not chunk:
                    break

                connection.sendall(chunk)

    return metadata

def canonical_file_metadata(metadata):
    """Create consistent bytes for HMAC verification."""

    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")