
import unittest

from src.peer_directory import PeerDirectory


class TestPeerDirectory(unittest.TestCase):

    def setUp(self):
        self.directory = PeerDirectory()

    def test_register_and_find_peers(self):
        self.directory.register("Peer A", "127.0.0.1", 5000)
        self.directory.register("Peer B", "127.0.0.1", 5001)

        peers = self.directory.get_peers()

        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0]["peer_id"], "Peer A")
        self.assertEqual(peers[1]["port"], 5001)

    def test_exclude_self(self):
        self.directory.register("Peer A", "127.0.0.1", 5000)
        self.directory.register("Peer B", "127.0.0.1", 5001)

        peers = self.directory.get_peers(exclude_peer_id="Peer A")

        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["peer_id"], "Peer B")

    def test_update_peer_address(self):
        self.directory.register("Peer A", "127.0.0.1", 5000)
        self.directory.register("Peer A", "127.0.0.1", 5002)

        peers = self.directory.get_peers()

        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["port"], 5002)

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            self.directory.register("Peer A", "127.0.0.1", 70000)


if __name__ == "__main__":
    unittest.main()
