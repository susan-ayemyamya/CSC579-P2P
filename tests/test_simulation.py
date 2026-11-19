"""
New file: tests for the simulation (simulation/engine.py and attacker.py).

Checks the generated overlay, that attackers are detected and
quarantined with the monitor on (and honest peers are not), and that
nobody is quarantined with the monitor off.
"""

import random
import time
import unittest

from simulation.attacker import AttackerPeer
from simulation.engine import Simulation, build_topology

FAST = dict(peers=8, attacker_ratio=0.25, attack_types=["replay", "tamper"],
            warmup=1.0, attack_interval=0.5, traffic_rate=4.0, seed=7)


# Wait until check() is true or the time runs out.
def wait_for(check, seconds=15.0):
    end = time.time() + seconds
    while time.time() < end:
        if check():
            return True
        time.sleep(0.2)
    return check()


class TestTopology(unittest.TestCase):

    def test_links_are_symmetric_and_connected(self):
        names = [f"P{i}" for i in range(20)]
        topology = build_topology(names, 3, random.Random(1))

        for name, neighbours in topology.items():
            self.assertGreaterEqual(len(neighbours), 2)
            for other in neighbours:
                self.assertIn(name, topology[other])

        seen, todo = set(), [names[0]]
        while todo:
            name = todo.pop()
            if name not in seen:
                seen.add(name)
                todo.extend(topology[name])
        self.assertEqual(seen, set(names))

    def test_invalid_settings_rejected(self):
        with self.assertRaises(ValueError):
            Simulation(peers=2)
        with self.assertRaises(ValueError):
            Simulation(attack_types=["unknown"])
        with self.assertRaises(ValueError):
            Simulation(colour="red")


class TestSimulationRuns(unittest.TestCase):

    def test_monitor_on_quarantines_attackers_only(self):
        simulation = Simulation(monitor_on=True, **FAST).start()
        try:
            self.assertEqual(len(simulation.attackers), 2)
            self.assertTrue(all(isinstance(a, AttackerPeer) for a in simulation.attackers.values()))
            self.assertTrue(wait_for(lambda: len(simulation.detected_at) == 2))

            summary = simulation.summary()
            self.assertEqual(summary["detection_rate"], 1.0)
            self.assertEqual(summary["false_positives"], 0)
            self.assertGreater(summary["delivered"], 0)
            self.assertTrue(set(simulation.attackers) <= simulation.bootstrap.quarantined)

            state = simulation.state()
            self.assertEqual(len(state["nodes"]), 8)
            self.assertTrue(state["alerts"])
        finally:
            simulation.stop()

    def test_monitor_off_quarantines_nobody(self):
        simulation = Simulation(monitor_on=False, **FAST).start()
        try:
            self.assertTrue(wait_for(lambda: sum(
                a.attacks_sent for a in simulation.attackers.values()) >= 6))
            summary = simulation.summary()
            self.assertEqual(summary["detected"], 0)
            self.assertEqual(simulation.quarantined(), set())
        finally:
            simulation.stop()


if __name__ == "__main__":
    unittest.main()
