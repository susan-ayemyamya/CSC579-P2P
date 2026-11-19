"""
New file: tests for the attack scripts (attacks/).

Each attack runs against a fresh overlay of real peers and must be
blocked and detected; where the proposal asks for a response, the
attacker must also be quarantined and avoided.
"""

import unittest

from attacks import fake_registration, impersonation, unauthorized_peer
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


if __name__ == "__main__":
    unittest.main()
