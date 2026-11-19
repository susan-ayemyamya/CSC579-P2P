"""
New file: the attack lab shared by all attack scripts.

Starts a real bootstrap server and four real peers on free ports of this
computer, with their own temporary keys:

        Peer A ---- Peer B ---- Peer D
          |                       |
          +-------- Peer C -------+

Peer A usually talks to Peer D through Peer B or Peer C. "Mallory" is an
outsider: she has a key pair, but it is not in the trusted list.
Each attack script runs one attack against this overlay and returns an
AttackResult saying whether the attack was blocked and detected, and
how the overlay responded.
"""

import os
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field

from src import config
from src.bootstrap import BootstrapServer
from src.encryption import encrypt_content, message_context
from src.identity import generate_keys, load_identity, load_trust_store
from src.message import canonical_routed_message, encode_secure_routed_message
from src.monitor import SecurityMonitor
from src.replay import new_freshness
from src.routed_peer import RoutedPeer, bootstrap_request, get_topology, send_routed_message
from src.security import calculate_hmac

TOPOLOGY = {
    "Peer A": ["Peer B", "Peer C"],
    "Peer B": ["Peer A", "Peer D"],
    "Peer C": ["Peer A", "Peer D"],
    "Peer D": ["Peer B", "Peer C"],
}
OUTSIDER = "Mallory"


# Outcome of one attack.
@dataclass
class AttackResult:
    name: str
    goal: str
    blocked: bool = False
    detected: bool = False
    response: str = "-"
    evidence: list = field(default_factory=list)

    @property
    def passed(self):
        return self.blocked and self.detected

    def lines(self):
        yes = {True: "YES", False: "NO"}
        return ([f"Attack:   {self.name}",
                 f"Goal:     {self.goal}",
                 f"Blocked:  {yes[self.blocked]}",
                 f"Detected: {yes[self.detected]}",
                 f"Response: {self.response}",
                 "Evidence:"]
                + [f"  - {line}" for line in self.evidence])


# A real overlay to attack; use it with "with AttackLab() as lab:".
class AttackLab:
    def __init__(self, flood_min_rate=None):
        self.flood_min_rate = flood_min_rate
        self.work_dir = None
        self.peers = {}
        self.bootstrap = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # Create keys, start the bootstrap server and the four peers.
    def start(self):
        self.work_dir = tempfile.mkdtemp(prefix="p2p_attack_")
        self.keys_dir = os.path.join(self.work_dir, "keys")
        self.outsider_dir = os.path.join(self.work_dir, "outsider_keys")
        self.alerts_dir = os.path.join(self.work_dir, "alerts")
        generate_keys(list(TOPOLOGY), self.keys_dir)
        generate_keys([OUTSIDER], self.outsider_dir)
        self.trust = load_trust_store(self.keys_dir)

        self.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False, keys_dir=self.keys_dir).start()
        self.bootstrap.monitor.alert_log = os.path.join(self.alerts_dir, "Bootstrap.log")
        self.bootstrap_address = ("127.0.0.1", self.bootstrap.port)

        for peer_id, neighbours in TOPOLOGY.items():
            monitor = SecurityMonitor(
                peer_id, verbose=False, flood_min_rate=self.flood_min_rate,
                alert_log=os.path.join(self.alerts_dir, peer_id.replace(" ", "_") + ".log"))
            self.peers[peer_id] = RoutedPeer(
                peer_id, port=0, file_port=0, neighbours=neighbours,
                bind_host="127.0.0.1", advertised_host="127.0.0.1",
                bootstrap_address=self.bootstrap_address, socket_timeout=3.0,
                shared_folder=self.work_dir,
                received_folder=os.path.join(self.work_dir, "received", peer_id),
                verbose=False, keys_dir=self.keys_dir, monitor=monitor,
            ).start()
        return self

    def stop(self):
        for peer in self.peers.values():
            peer.stop()
        if self.bootstrap is not None:
            self.bootstrap.stop()
        if self.work_dir:
            shutil.rmtree(self.work_dir, ignore_errors=True)

    # ------------------------------------------------------------
    # Tools for the attacker
    # ------------------------------------------------------------

    # Private key of a peer (or of the outsider).
    def identity(self, name):
        keys = self.outsider_dir if name == OUTSIDER else self.keys_dir
        return load_identity(name, keys)

    # Build a routed message, by default exactly as an honest sender would.
    #   signer:    whose key signs it (default: the sender's own key)
    #   freshness: msg_id, nonce and timestamp (default: new ones)
    def message(self, sender, destination, route, text="hello", signer=None, freshness=None):
        freshness = freshness or new_freshness()
        content = encrypt_content(text, self.trust.encryption_key(destination),
                                  message_context(sender, destination, freshness["msg_id"]))
        original = canonical_routed_message(sender, destination, content, route, freshness)
        signature = (signer or self.identity(sender)).sign(original)
        return encode_secure_routed_message(
            sender, destination, content, route,
            calculate_hmac(original, config.SECRET_KEY), freshness, signature)

    # Send raw bytes straight to a peer; returns its reply (b"" = dropped).
    def send_raw(self, peer_id, payload):
        address = ("127.0.0.1", self.peers[peer_id].port)
        with socket.create_connection(address, timeout=5) as connection:
            connection.sendall(payload)
            with connection.makefile("rb") as stream:
                return stream.readline(config.MAX_MESSAGE_SIZE + 1)

    # Send a request to the bootstrap server; errors become a response.
    def bootstrap_call(self, request):
        try:
            return bootstrap_request(request, self.bootstrap_address)
        except RuntimeError as error:
            return {"status": "error", "message": str(error)}

    # An honest message through the overlay (route chosen by the sender).
    def honest_send(self, sender="Peer A", destination="Peer D"):
        try:
            return send_routed_message(sender, destination, "honest traffic",
                                       bootstrap_address=self.bootstrap_address,
                                       verbose=False, keys_dir=self.keys_dir)
        except Exception as error:
            return {"status": "failed", "error": str(error), "route": None}

    # ------------------------------------------------------------
    # What the defenders saw
    # ------------------------------------------------------------

    def alerts(self, peer_id):
        if peer_id == "Bootstrap":
            return list(self.bootstrap.monitor.alerts)
        return list(self.peers[peer_id].monitor.alerts)

    def directory(self):
        return {p["peer_id"]: p for p in get_topology(self.bootstrap_address)}

    def quarantined_overlay(self):
        return {name for name, peer in self.directory().items() if peer.get("quarantined")}


# Wait until check() is true (reports to the bootstrap server take a moment).
def wait_until(check, seconds=5.0):
    end = time.time() + seconds
    while time.time() < end:
        if check():
            return True
        time.sleep(0.05)
    return check()


# Short form of an alert line: who raised it and the text, without the time.
def short(alert):
    if "[" in alert and "ALERT: " in alert:
        owner = alert.split("[", 1)[1].split("]", 1)[0]
        return f"{owner}: {alert.split('ALERT: ', 1)[1]}"
    return alert


# Run one attack script from the command line and print its result.
def run_script(attack):
    with AttackLab() as lab:
        result = attack(lab)
    print("\n".join(result.lines()))
    return 0 if result.passed else 1
