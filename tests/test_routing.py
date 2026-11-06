
import unittest

from src.routing import get_next_hop


class TestRouting(unittest.TestCase):

    def setUp(self):
        self.routing_table = {
            "Peer B": "Peer B",
            "Peer C": "Peer B",
        }

    def test_direct_next_hop(self):
        result = get_next_hop("Peer B", self.routing_table)
        self.assertEqual(result, "Peer B")

    def test_indirect_next_hop(self):
        result = get_next_hop("Peer C", self.routing_table)
        self.assertEqual(result, "Peer B")

    def test_unknown_destination(self):
        result = get_next_hop("Peer D", self.routing_table)
        self.assertIsNone(result)

    def test_empty_destination(self):
        with self.assertRaises(ValueError):
            get_next_hop("", self.routing_table)

    def test_invalid_routing_table(self):
        with self.assertRaises(ValueError):
            get_next_hop("Peer C", [])

    def test_invalid_next_hop(self):
        invalid_table = {"Peer C": ""}
        with self.assertRaises(ValueError):
            get_next_hop("Peer C", invalid_table)


if __name__ == "__main__":
    unittest.main()
