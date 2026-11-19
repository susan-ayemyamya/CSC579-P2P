"""
New file: attacker peers for the simulation.

An attacker is a real, registered peer (an insider: it has its own key
and knows the shared HMAC key). Once the attack phase starts it:
  - silently drops messages it should forward to other peers (black hole)
  - attacks one of its honest neighbours with one behaviour:
      replay       sends a message, then sends the same bytes again
      tamper       changes the content of a signed message
      impersonate  claims that a message comes from another peer
      flood        sends a burst of valid messages within one second
      on-off       replays in short bursts with long quiet periods
"""

import random
import socket

from src import config
from src.encryption import encrypt_content, message_context
from src.message import canonical_routed_message, encode_secure_routed_message
from src.replay import new_freshness
from src.routed_peer import RoutedPeer
from src.security import calculate_hmac

ATTACK_TYPES = ["replay", "tamper", "impersonate", "flood", "on-off"]

FLOOD_BURST = 40     # messages per flood burst
ON_OFF_CYCLE = 5     # on-off attacker attacks once every 5 rounds


# A registered peer that drops traffic and attacks its neighbours.
class AttackerPeer(RoutedPeer):
    def __init__(self, *args, attack="replay", drop_traffic=True,
                 honest_peers=(), rng=None, **kwargs):
        super().__init__(*args, **kwargs)
        if attack not in ATTACK_TYPES:
            raise ValueError(f"Unknown attack: {attack}")
        self.attack = attack
        self.drop_traffic = drop_traffic
        self.honest_peers = list(honest_peers)
        self.rng = rng or random.Random()
        self.active = False
        self.rounds = 0
        self.attacks_sent = 0
        self.dropped = 0
        self.first_attack = None

    # Black hole: while active, messages for other peers are dropped.
    def forward_routed_message(self, sender, destination, content, route,
                               tag, freshness, signature):
        if self.active and self.drop_traffic and destination != self.peer_id:
            self.dropped += 1
            raise ValueError("Dropped by attacker")
        return super().forward_routed_message(
            sender, destination, content, route, tag, freshness, signature)

    # One attack round against a random honest neighbour.
    def attack_round(self, now):
        self.rounds += 1
        targets = [p for p in self.neighbours if p in self.honest_peers]
        if not targets:
            return 0
        if self.attack == "on-off" and (self.rounds - 1) % ON_OFF_CYCLE:
            return 0

        target = self.rng.choice(targets)
        if self.first_attack is None:
            self.first_attack = now

        if self.attack in ("replay", "on-off"):
            line = self._message(target)
            sent = self._send(target, line) + self._send(target, line)
        elif self.attack == "tamper":
            sent = self._send(target, self._tampered(target))
        elif self.attack == "impersonate":
            sent = self._send(target, self._impersonated(target))
        else:
            sent = sum(self._send(target, self._message(target)) for _ in range(FLOOD_BURST))

        self.attacks_sent += sent
        return sent

    # A valid message from this peer to a neighbour.
    def _message(self, target, sender=None, signer=None, text="hello"):
        sender = sender or self.peer_id
        freshness = new_freshness()
        content = encrypt_content(text, self.trust_store.encryption_key(target),
                                  message_context(sender, target, freshness["msg_id"]))
        route = [self.peer_id, target] if sender == self.peer_id else [sender, self.peer_id, target]
        original = canonical_routed_message(sender, target, content, route, freshness)
        signature = (signer or self.identity).sign(original)
        return encode_secure_routed_message(
            sender, target, content, route,
            calculate_hmac(original, config.SECRET_KEY), freshness, signature)

    # Signed message whose content is changed afterwards (HMAC recomputed).
    def _tampered(self, target):
        freshness = new_freshness()
        context = message_context(self.peer_id, target, freshness["msg_id"])
        key = self.trust_store.encryption_key(target)
        route = [self.peer_id, target]
        original = canonical_routed_message(
            self.peer_id, target, encrypt_content("pay 10", key, context), route, freshness)
        signature = self.identity.sign(original)
        changed = encrypt_content("pay 1000", key, context)
        forged = canonical_routed_message(self.peer_id, target, changed, route, freshness)
        return encode_secure_routed_message(
            self.peer_id, target, changed, route,
            calculate_hmac(forged, config.SECRET_KEY), freshness, signature)

    # Message that claims another peer as sender but is signed by this peer.
    def _impersonated(self, target):
        victims = [p for p in self.honest_peers if p != target]
        if not victims:
            return self._tampered(target)
        return self._message(target, sender=self.rng.choice(victims))

    # Send raw bytes straight to a neighbour; 1 if it was sent.
    def _send(self, target, payload):
        record = self._peer_record(target)
        if record is None:
            return 0
        try:
            with socket.create_connection((record["host"], record["port"]),
                                          timeout=self.socket_timeout) as connection:
                connection.sendall(payload)
                with connection.makefile("rb") as stream:
                    stream.readline(config.MAX_MESSAGE_SIZE + 1)
            return 1
        except OSError:
            return 0
