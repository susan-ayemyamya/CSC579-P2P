"""
New file: tests for the security monitor (detection and response).

Checks the trust score, time decay, on-off attacks, the 3-sigma flood
rule and quarantine on their own.
"""

import os
import shutil
import tempfile
import unittest

from src import config
from src.monitor import SecurityMonitor


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


if __name__ == "__main__":
    unittest.main()
