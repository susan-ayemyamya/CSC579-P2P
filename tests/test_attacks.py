"""
New file: tests for the attack scripts (attacks/).

Each attack runs against a fresh overlay of real peers and must be
blocked and detected; where the proposal asks for a response, the
attacker must also be quarantined and avoided.
"""

import contextlib
import io
import os
import tempfile
import unittest

from attacks import (fake_registration, flooding, impersonation, replay_attack,
                     tampering, unauthorized_peer)
from attacks import run_all
from attacks.lab import AttackLab


class AttackTestCase(unittest.TestCase):

    def run_attack(self, attack):
        with AttackLab() as lab:
            result = attack.run(lab)
        self.assertTrue(result.blocked, "\n".join(result.lines()))
        self.assertTrue(result.detected, "\n".join(result.lines()))
        return result


class TestIdentityAttacks(AttackTestCase):

    def test_unauthorized_peer(self):
        self.run_attack(unauthorized_peer)

    def test_fake_registration(self):
        self.run_attack(fake_registration)

    def test_impersonation(self):
        result = self.run_attack(impersonation)
        self.assertIn("quarantined", result.response)


class TestMessageAttacks(AttackTestCase):

    def test_tampering(self):
        result = self.run_attack(tampering)
        self.assertIn("quarantined", result.response)

    def test_replay(self):
        result = self.run_attack(replay_attack)
        self.assertIn("quarantined", result.response)

    def test_flooding(self):
        result = self.run_attack(flooding)
        self.assertIn("quarantined", result.response)


class TestRunAll(unittest.TestCase):

    def test_summary_table_and_csv(self):
        folder = tempfile.mkdtemp()
        path = os.path.join(folder, "results.csv")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = run_all.main(["unauthorized_peer", "replay", "--csv", path])
        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("2 of 2 attacks blocked and detected", text)
        self.assertIn("Unauthorized peer", text)
        with open(path, encoding="utf-8") as file:
            self.assertEqual(len(file.read().strip().splitlines()), 3)

    def test_every_attack_is_registered(self):
        self.assertEqual(len(run_all.ATTACKS), 6)

    def test_unknown_attack_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            run_all.main(["nonsense"])


if __name__ == "__main__":
    unittest.main()
