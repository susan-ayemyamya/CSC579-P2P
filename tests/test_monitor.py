"""
New file: tests for the security monitor (detection and response).

Checks the trust score, time decay, on-off attacks, the 3-sigma flood
rule and quarantine on their own; the bootstrap server's quarantine
reports; and real peers where an insider replays messages, gets
quarantined, is reported, and traffic is routed around it. Normal
traffic must not raise any alert (no false positives).
"""

import os
import shutil
import socket
import tempfile
import unittest

from src import config
from src.bootstrap import BootstrapServer
from src.encryption import encrypt_content, message_context
from src.identity import generate_keys, load_identity, load_trust_store, sign_request
from src.message import canonical_routed_message, encode_secure_routed_message
from src.monitor import SecurityMonitor
from src.replay import new_freshness
from src.routed_peer import RoutedPeer, get_topology, send_routed_message
from src.security import calculate_hmac

KEY = config.SECRET_KEY


# A clock the tests can move by hand (seconds).
class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


# Trust, decay, quarantine and flood detection on their own.
class TestTrustScore(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock()
        self.reported = []
        self.monitor = SecurityMonitor(
            "B", clock=self.clock, verbose=False,
            on_quarantine=lambda source, event: self.reported.append(source),
        )

    def test_new_source_has_full_trust(self):
        self.assertEqual(self.monitor.trust("A"), 1.0)

    def test_example_from_the_mapping(self):
        # Two failed HMAC checks and one replay: 1.0 -> 0.8 -> 0.6 -> 0.3.
        self.assertAlmostEqual(self.monitor.record("A", "bad_hmac"), 0.8)
        self.assertAlmostEqual(self.monitor.record("A", "bad_hmac"), 0.6)
        self.assertFalse(self.monitor.is_quarantined("A"))
        self.assertAlmostEqual(self.monitor.record("A", "replay"), 0.3)

        self.assertTrue(self.monitor.is_quarantined("A"))
        self.assertEqual(self.reported, ["A"])

    def test_single_mistake_does_not_quarantine(self):
        self.monitor.record("A", "replay")
        self.assertFalse(self.monitor.is_quarantined("A"))

    def test_old_events_fade(self):
        self.monitor.record("A", "replay")
        self.clock.now += 60
        # 0.3 * 0.9 ** 6 is about 0.16, so trust is back to about 0.84.
        self.assertGreater(self.monitor.trust("A"), 0.8)

    def test_on_off_attacker_still_quarantined(self):
        # Attacks every 20 seconds, behaving in between.
        for _ in range(4):
            self.monitor.record("A", "replay")
            self.clock.now += 20
        self.assertTrue(self.monitor.is_quarantined("A"))

    def test_rare_glitches_do_not_quarantine(self):
        # One failure every 5 minutes is normal noise, not an attack.
        for _ in range(5):
            self.monitor.record("A", "bad_hmac")
            self.clock.now += 300
        self.assertFalse(self.monitor.is_quarantined("A"))

    def test_quarantine_stays_until_released(self):
        for _ in range(3):
            self.monitor.record("A", "bad_signature")
        self.clock.now += 3600
        self.assertTrue(self.monitor.is_quarantined("A"))

        self.monitor.release("A")
        self.assertFalse(self.monitor.is_quarantined("A"))
        self.assertEqual(self.monitor.trust("A"), 1.0)

    def test_alert_log_written(self):
        folder = tempfile.mkdtemp()
        try:
            log = os.path.join(folder, "B.log")
            monitor = SecurityMonitor("B", clock=self.clock, verbose=False, alert_log=log)
            for _ in range(3):
                monitor.record("A", "replay")
            with open(log, encoding="utf-8") as file:
                text = file.read()
            self.assertIn("QUARANTINED A", text)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class TestFloodDetection(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock(2000.0)
        self.monitor = SecurityMonitor("B", clock=self.clock, verbose=False, flood_min_rate=10)

    # Send 'count' messages from a source within one second.
    def burst(self, source, count):
        return any([self.monitor.observe(source) for _ in range(count)])

    def test_normal_rate_is_not_a_flood(self):
        for second in range(20):
            self.clock.now = 2000 + second
            self.assertFalse(self.burst("A", 5))
        self.assertEqual(self.monitor.trust("A"), 1.0)

    def test_sudden_spike_is_a_flood(self):
        for second in range(10):
            self.clock.now = 2000 + second
            self.burst("A", 4)
        self.clock.now = 2010
        self.assertTrue(self.burst("A", 30))
        self.assertLess(self.monitor.trust("A"), 1.0)

    def test_steady_high_rate_learned_as_normal(self):
        # A busy but steady peer: once its normal rate is known (after a
        # few seconds), the same rate is no longer a flood.
        for second in range(10):
            self.clock.now = 2000 + second
            self.burst("A", 15)
        self.clock.now = 2010
        self.assertFalse(self.burst("A", 15))

    def test_flood_counted_once_per_second(self):
        self.clock.now = 2000
        self.burst("A", 50)
        self.assertAlmostEqual(self.monitor.trust("A"), 1.0 - config.PENALTIES["flood"])

    def test_repeated_floods_lead_to_quarantine(self):
        for second in range(3):
            self.clock.now = 2000 + second
            self.burst("A", 50)
        self.assertTrue(self.monitor.is_quarantined("A"))


# The bootstrap server's quarantine list (no network needed).
class TestQuarantineReports(unittest.TestCase):

    def setUp(self):
        self.keys_dir = tempfile.mkdtemp()
        generate_keys(["A", "B", "C"], self.keys_dir)
        self.server = BootstrapServer(verbose=False, keys_dir=self.keys_dir)
        self.server.monitor.alert_log = None
        self.ids = {p: load_identity(p, self.keys_dir) for p in "ABC"}

        for peer_id in "ABC":
            self.server.process_request(sign_request({
                "action": "register", "peer_id": peer_id, "host": "127.0.0.1",
                "port": 5000, "freshness": new_freshness(),
            }, self.ids[peer_id]), ("127.0.0.1", 0))

    def tearDown(self):
        shutil.rmtree(self.keys_dir, ignore_errors=True)

    def report(self, reporter, suspect, signed=True):
        request = {"action": "report", "peer_id": reporter, "suspect": suspect,
                   "reason": "replay", "freshness": new_freshness()}
        if signed:
            request = sign_request(request, self.ids[reporter])
        return self.server.process_request(request, ("127.0.0.1", 0))

    def flags(self):
        peers = self.server.process_request(
            {"action": "topology", "peer_id": "client"}, None)["peers"]
        return {peer["peer_id"]: peer["quarantined"] for peer in peers}

    def test_nobody_quarantined_at_start(self):
        self.assertEqual(self.flags(), {"A": False, "B": False, "C": False})

    def test_signed_report_quarantines_peer(self):
        self.assertEqual(self.report("C", "B")["status"], "ok")
        self.assertTrue(self.flags()["B"])

    def test_unsigned_report_ignored(self):
        self.assertEqual(self.report("C", "B", signed=False)["status"], "error")
        self.assertFalse(self.flags()["B"])

    def test_peer_cannot_report_itself(self):
        with self.assertRaises(ValueError):
            self.report("B", "B")

    def test_rejected_join_raises_alert(self):
        self.server.process_request({
            "action": "register", "peer_id": "Z", "host": "10.0.0.9",
            "port": 5000, "freshness": new_freshness(),
        }, ("10.0.0.9", 1234))
        self.assertTrue(any("unauthorized_join" in line for line in self.server.monitor.alerts))


# Real bootstrap server and four peers:  A - B - D  and  A - C - D.
class TestLiveDetectionAndResponse(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp()
        cls.keys_dir = os.path.join(cls.work_dir, "keys")
        generate_keys(["A", "B", "C", "D"], cls.keys_dir)
        cls.trust = load_trust_store(cls.keys_dir)
        cls.id_a = load_identity("A", cls.keys_dir)

        cls.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False, keys_dir=cls.keys_dir
        ).start()
        cls.bootstrap.monitor.alert_log = None
        cls.bootstrap_address = ("127.0.0.1", cls.bootstrap.port)

        cls.peers = {}
        topology = {"A": ["B", "C"], "B": ["A", "D"], "C": ["A", "D"], "D": ["B", "C"]}
        for peer_id, neighbours in topology.items():
            monitor = SecurityMonitor(
                peer_id, verbose=False, flood_min_rate=10,
                alert_log=os.path.join(cls.work_dir, "alerts", f"{peer_id}.log"),
            )
            cls.peers[peer_id] = RoutedPeer(
                peer_id, port=0, file_port=0, neighbours=neighbours,
                bind_host="127.0.0.1", advertised_host="127.0.0.1",
                bootstrap_address=cls.bootstrap_address, socket_timeout=2.0,
                shared_folder=cls.work_dir,
                received_folder=os.path.join(cls.work_dir, "recv", peer_id),
                verbose=False, keys_dir=cls.keys_dir, monitor=monitor,
            ).start()

        cls.address_d = ("127.0.0.1", cls.peers["D"].port)

    @classmethod
    def tearDownClass(cls):
        for peer in cls.peers.values():
            peer.stop()
        cls.bootstrap.stop()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    # A valid message from A to D along 'route' (encrypted for D, signed by A).
    def message(self, route, text="hello"):
        freshness = new_freshness()
        content = encrypt_content(text, self.trust.encryption_key("D"),
                                  message_context("A", "D", freshness["msg_id"]))
        original = canonical_routed_message("A", "D", content, route, freshness)
        return encode_secure_routed_message(
            "A", "D", content, route, calculate_hmac(original, KEY), freshness,
            self.id_a.sign(original),
        )

    # Send raw bytes straight to Peer D, as if a neighbour forwarded them.
    def to_d(self, payload):
        with socket.create_connection(self.address_d, timeout=5) as connection:
            connection.sendall(payload)
            with connection.makefile("rb") as stream:
                return stream.readline(config.MAX_MESSAGE_SIZE + 1)

    def send(self, destination="D"):
        return send_routed_message("A", destination, "normal traffic",
                                   bootstrap_address=self.bootstrap_address,
                                   verbose=False, keys_dir=self.keys_dir)

    def test_1_normal_traffic_raises_no_alerts(self):
        for _ in range(5):
            self.assertEqual(self.send()["status"], "ok")
        for peer in self.peers.values():
            self.assertEqual(peer.monitor.alerts, [])

    def test_2_insider_replaying_is_quarantined_and_avoided(self):
        # B keeps replaying a captured message to D.
        line = self.message(["A", "B", "D"])
        self.assertTrue(self.to_d(line))          # first copy is genuine
        for _ in range(3):
            self.assertEqual(self.to_d(line), b"")  # replays are dropped

        # D detected it and quarantined B ...
        monitor = self.peers["D"].monitor
        self.assertTrue(monitor.is_quarantined("B"))
        self.assertLess(monitor.trust("B"), config.TRUST_THRESHOLD)

        # ... wrote an alert ...
        with open(os.path.join(self.work_dir, "alerts", "D.log"), encoding="utf-8") as file:
            self.assertIn("QUARANTINED B", file.read())

        # ... reported B, so the whole overlay knows ...
        flags = {p["peer_id"]: p["quarantined"] for p in get_topology(self.bootstrap_address)}
        self.assertTrue(flags["B"])

        # ... and new messages from A to D go around B.
        result = self.send()
        self.assertEqual(result["route"], ["A", "C", "D"])

        # Anything still arriving through B is dropped by D.
        self.assertEqual(self.to_d(self.message(["A", "B", "D"])), b"")

    def test_3_flood_is_detected(self):
        # C suddenly forwards many messages to D within one second.
        for _ in range(15):
            self.to_d(self.message(["A", "C", "D"]))
        self.assertTrue(any("flood from C" in line for line in self.peers["D"].monitor.alerts))


if __name__ == "__main__":
    unittest.main()
