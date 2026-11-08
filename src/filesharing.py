
import os
import hashlib
import json
import socket

from src.security import calculate_hmac, verify_hmac

CHUNK_SIZE = 4096
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
SECRET_KEY = b"demo-shared-key-change-later"

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


def receive_file(connection, destination_folder):
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

def send_file(host, port, file_path):
    """Send a file with HMAC-authenticated metadata."""

    metadata = get_file_metadata(file_path)

    if metadata["file_size"] > MAX_FILE_SIZE:
        raise ValueError("File size exceeds the 10 MB limit")

    # Create canonical metadata bytes.
    original_bytes = canonical_file_metadata(metadata)

    # Generate HMAC authentication tag.
    tag = calculate_hmac(original_bytes, SECRET_KEY)

    # Package metadata and authentication tag.
    envelope = {
        "metadata": metadata,
        "tag": tag,
    }

    with socket.create_connection(
        (host, port),
        timeout=10
    ) as connection:

        # Send metadata envelope first.
        metadata_bytes = (
            json.dumps(envelope).encode("utf-8") + b"\n"
        )

        connection.sendall(metadata_bytes)

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