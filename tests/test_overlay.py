"""
New file: tests for the overlay routing.

Checks that the peer directory stores neighbours and file ports,
that routes are computed correctly (including avoiding a peer), and
runs a real bootstrap server with five peers to test multi-hop
delivery, file requests, refused shortcuts, and that a silent
client does not block a peer.

"""

import os
import shutil
import socket
import tempfile
import time
import unittest

from src.bootstrap import BootstrapServer
from src.peer_directory import PeerDirectory
from src.routed_peer import (
    RoutedPeer,
    get_topology,
    request_file,
    send_routed_message,
)
from src.routing import build_graph, build_routing_table, shortest_path


# Directory stores and checks neighbours and file ports.
class TestDirectoryNeighbours(unittest.TestCase):

    def test_neighbours_and_file_port_are_stored(self):
        directory = PeerDirectory()
        directory.register("Peer A", "127.0.0.1", 5000, 5100, ["Peer B"])

        peer = directory.get_peers()[0]

        self.assertEqual(peer["file_port"], 5100)
        self.assertEqual(peer["neighbours"], ["Peer B"])

    def test_peer_cannot_be_its_own_neighbour(self):
        directory = PeerDirectory()

        with self.assertRaises(ValueError):
            directory.register("Peer A", "127.0.0.1", 5000, None, ["Peer A"])


# Route calculation, without any network.
class TestGraphRouting(unittest.TestCase):

    def setUp(self):
        # A - B - D - E and A - C - D
        self.graph = build_graph([
            {"peer_id": "A", "neighbours": ["B", "C"]},
            {"peer_id": "B", "neighbours": ["D"]},
            {"peer_id": "C", "neighbours": ["D"]},
            {"peer_id": "D", "neighbours": ["E"]},
            {"peer_id": "E", "neighbours": []},
        ])

    def test_links_are_undirected(self):
        self.assertIn("A", self.graph["B"])
        self.assertIn("D", self.graph["E"])

    def test_shortest_route(self):
        self.assertEqual(
            shortest_path(self.graph, "A", "E"),
            ["A", "B", "D", "E"],
        )

    def test_route_avoids_excluded_peer(self):
        self.assertEqual(
            shortest_path(self.graph, "A", "E", excluded={"B"}),
            ["A", "C", "D", "E"],
        )

    def test_no_route(self):
        self.assertIsNone(
            shortest_path(self.graph, "A", "E", excluded={"D"})
        )

    def test_routing_table_matches_original_format(self):
        table = build_routing_table(self.graph, "A")
        self.assertEqual(table["E"], "B")
        self.assertEqual(table["C"], "C")

    def test_original_three_peer_routes(self):
        graph = build_graph([
            {"peer_id": "Peer A", "neighbours": ["Peer B"]},
            {"peer_id": "Peer B", "neighbours": ["Peer A", "Peer C"]},
            {"peer_id": "Peer C", "neighbours": ["Peer B"]},
        ])

        # Same as the original ROUTING_TABLES.
        self.assertEqual(build_routing_table(graph, "Peer A")["Peer C"], "Peer B")
        self.assertEqual(build_routing_table(graph, "Peer B")["Peer C"], "Peer C")


# Start a real bootstrap server and five peers on free ports.
class TestLiveOverlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp()
        cls.shared = os.path.join(cls.work_dir, "shared")
        os.makedirs(cls.shared)

        with open(os.path.join(cls.shared, "notes.txt"), "wb") as file:
            file.write(b"overlay test file\n")

        cls.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False
        ).start()
        cls.bootstrap_address = ("127.0.0.1", cls.bootstrap.port)

        # A - B - D - E and A - C - D
        topology = {
            "A": ["B", "C"],
            "B": ["A", "D"],
            "C": ["A", "D"],
            "D": ["B", "C", "E"],
            "E": ["D"],
        }

        cls.peers = {}

        for peer_id, neighbours in topology.items():
            cls.peers[peer_id] = RoutedPeer(
                peer_id,
                port=0,
                file_port=0,
                neighbours=neighbours,
                bind_host="127.0.0.1",
                advertised_host="127.0.0.1",
                bootstrap_address=cls.bootstrap_address,
                socket_timeout=2.0,
                shared_folder=cls.shared,
                received_folder=os.path.join(cls.work_dir, "recv", peer_id),
                verbose=False,
            ).start()

    @classmethod
    def tearDownClass(cls):
        for peer in cls.peers.values():
            peer.stop()

        cls.bootstrap.stop()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def send(self, sender, destination, content, **options):
        return send_routed_message(
            sender, destination, content,
            bootstrap_address=self.bootstrap_address,
            verbose=False,
            **options,
        )

    def test_all_peers_registered(self):
        peers = get_topology(self.bootstrap_address)
        self.assertEqual(
            sorted(peer["peer_id"] for peer in peers),
            ["A", "B", "C", "D", "E"],
        )

    def test_multi_hop_delivery(self):
        result = self.send("A", "E", "hello")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["route"], ["A", "B", "D", "E"])
        self.assertEqual(result["hops"], 3)

    def test_route_avoiding_a_peer(self):
        # This is how traffic will avoid a quarantined peer in Step 6.
        result = self.send("A", "E", "avoid B", excluded={"B"})

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["route"], ["A", "C", "D", "E"])

    def test_route_over_missing_link_is_refused(self):
        # A and E are not neighbours, so A must not send directly to E.
        with self.assertRaises((ValueError, OSError)):
            self.send("A", "E", "shortcut", route=["A", "E"])

    def test_file_request_through_overlay(self):
        request_file(
            "notes.txt",
            requester="A",
            owner="E",
            bootstrap_address=self.bootstrap_address,
            verbose=False,
        )

        received = os.path.join(self.work_dir, "recv", "A", "notes.txt")

        # The file is sent on a separate connection and written in
        # chunks, so wait until the whole content has arrived.
        expected = b"overlay test file\n"
        content = b""

        for _ in range(50):
            if os.path.isfile(received):
                with open(received, "rb") as file:
                    content = file.read()
                if content == expected:
                    break
            time.sleep(0.1)

        self.assertEqual(content, expected)

    def test_silent_client_does_not_block_peer(self):
        # A client connects to Peer A and never sends anything.
        address = ("127.0.0.1", self.peers["A"].port)

        with socket.create_connection(address, timeout=5):
            # Peer A must still serve other messages at the same time.
            result = self.send("A", "E", "still working")

        self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
