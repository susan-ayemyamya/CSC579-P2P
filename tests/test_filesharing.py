import json
import os
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from src.security import calculate_hmac

from src.filesharing import (
    send_file,
    receive_file,
    calculate_file_hash,
    get_file_metadata,
    canonical_file_metadata,
    SECRET_KEY,
)


class TestFileSharing(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.file_path = os.path.join(
            self.temp_dir.name,
            "sample.txt"
        )

        with open(self.file_path, "wb") as file:
            file.write(
                b"This is a test file for our secure P2P file sharing project.\r\n"
            )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_calculate_file_hash(self):
        file_hash = calculate_file_hash(self.file_path)

        self.assertEqual(len(file_hash), 64)

        self.assertEqual(
            file_hash,
            "b7de25ff52067ad679e4c808772ac8f18deb761f5338e068016010d3f123a5bb"
        )

    def test_get_file_metadata(self):
        metadata = get_file_metadata(self.file_path)

        self.assertEqual(metadata["filename"], "sample.txt")
        self.assertEqual(metadata["file_size"], 62)

        self.assertEqual(
            metadata["sha256"],
            calculate_file_hash(self.file_path)
        )

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            get_file_metadata("nonexistent_file.txt")

    def test_send_and_receive_file(self):
        destination_folder = os.path.join(
            self.temp_dir.name,
            "received"
        )

        received_results = []

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as server:

            server.bind(("127.0.0.1", 0))
            server.listen(1)

            host, port = server.getsockname()

            def receiver():
                connection, address = server.accept()

                with connection:
                    result = receive_file(
                        connection,
                        destination_folder
                    )
                    received_results.append(result)

            receiver_thread = threading.Thread(
                target=receiver
            )

            receiver_thread.start()

            send_file(
                host,
                port,
                self.file_path
            )

            receiver_thread.join(timeout=10)

            self.assertFalse(
                receiver_thread.is_alive(),
                "Receiver thread did not finish"
            )

        received_path = os.path.join(
            destination_folder,
            "sample.txt"
        )

        self.assertTrue(os.path.isfile(received_path))

        self.assertEqual(
            calculate_file_hash(self.file_path),
            calculate_file_hash(received_path)
        )

        self.assertEqual(
            received_results[0]["status"],
            "verified"
        )

    def test_forged_metadata_is_rejected(self):
        receiver_socket, sender_socket = socket.socketpair()

        errors = []

        def receiver():
            with receiver_socket:
                try:
                    receive_file(
                        receiver_socket,
                        os.path.join(
                            self.temp_dir.name,
                            "forged_received"
                        )
                    )
                except Exception as error:
                    errors.append(error)

        receiver_thread = threading.Thread(target=receiver)
        receiver_thread.start()

        metadata = get_file_metadata(self.file_path)

        forged_envelope = {
            "metadata": metadata,
            "tag": "0" * 64,
        }

        with sender_socket:
            sender_socket.sendall(
                json.dumps(forged_envelope).encode("utf-8") + b"\n"
            )

        receiver_thread.join(timeout=10)

        self.assertFalse(
            receiver_thread.is_alive(),
            "Receiver thread did not finish"
        )

        self.assertEqual(len(errors), 1)

        self.assertIsInstance(errors[0], ValueError)

        self.assertEqual(
            str(errors[0]),
            "File metadata authentication failed"
        )

    def test_wrong_key_is_rejected(self):
        receiver_socket, sender_socket = socket.socketpair()

        errors = []

        metadata = get_file_metadata(self.file_path)

        original_bytes = canonical_file_metadata(metadata)

        tag = calculate_hmac(original_bytes, SECRET_KEY)

        envelope = {
            "metadata": metadata,
            "tag": tag,
        }

        def receiver():
            with receiver_socket:
                with patch(
                    "src.filesharing.SECRET_KEY",
                    b"incorrect-demo-key"
                ):
                    try:
                        receive_file(
                            receiver_socket,
                            os.path.join(
                                self.temp_dir.name,
                                "wrong_key_received"
                            )
                        )
                    except Exception as error:
                        errors.append(error)

        receiver_thread = threading.Thread(target=receiver)
        receiver_thread.start()

        with sender_socket:
            sender_socket.sendall(
                json.dumps(envelope).encode("utf-8") + b"\n"
            )

        receiver_thread.join(timeout=10)

        self.assertFalse(
            receiver_thread.is_alive(),
            "Receiver thread did not finish"
        )

        self.assertEqual(len(errors), 1)

        self.assertIsInstance(errors[0], ValueError)

        self.assertEqual(
            str(errors[0]),
            "File metadata authentication failed"
        )

    def test_modified_file_content_is_rejected(self):
        receiver_socket, sender_socket = socket.socketpair()
        errors = []

        metadata = get_file_metadata(self.file_path)
        original_bytes = canonical_file_metadata(metadata)
        tag = calculate_hmac(original_bytes, SECRET_KEY)

        envelope = {
            "metadata": metadata,
            "tag": tag,
        }

        with open(self.file_path, "rb") as file:
            original_content = file.read()

        modified_content = b"X" + original_content[1:]

        destination_folder = os.path.join(
            self.temp_dir.name,
            "tampered_received"
        )

        def receiver():
            with receiver_socket:
                try:
                    receive_file(receiver_socket, destination_folder)
                except Exception as error:
                    errors.append(error)

        receiver_thread = threading.Thread(target=receiver)
        receiver_thread.start()

        with sender_socket:
            sender_socket.sendall(
                json.dumps(envelope).encode("utf-8") + b"\n"
            )
            sender_socket.sendall(modified_content)

        receiver_thread.join(timeout=10)

        self.assertFalse(receiver_thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)
        self.assertEqual(
            str(errors[0]),
            "File integrity verification failed"
        )

        received_path = os.path.join(
            destination_folder,
            "sample.txt"
        )

        self.assertFalse(os.path.exists(received_path))

    def test_sender_rejects_oversized_file(self):
        with patch("src.filesharing.MAX_FILE_SIZE", 10):
            with patch("src.filesharing.socket.create_connection") as mock_connection:

                with self.assertRaisesRegex(
                    ValueError,
                    "File size exceeds the 10 MB limit"
                ):
                    send_file("127.0.0.1", 5000, self.file_path)

                mock_connection.assert_not_called()

if __name__ == "__main__":
    unittest.main()