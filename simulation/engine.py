"""
New file: the simulation engine.

Starts a bootstrap server and N peers on this computer, all running the
project's real code (RoutedPeer, signed registration, encryption,
replay protection and the security monitor). A share of the peers are
attackers (simulation/attacker.py). Honest peers keep sending messages
to each other, and the engine measures:
  - delivery rate (overall and over the last few seconds)
  - round-trip time and hop count of delivered messages
  - which attackers were detected (quarantined) and how fast
  - false positives (honest peers quarantined)

With the monitor switched off, peers still reject bad messages but
never quarantine anyone, so the two modes can be compared.
"""

import collections
import os
import random
import shutil
import statistics
import tempfile
import threading
import time

from src.bootstrap import BootstrapServer
from src.identity import generate_keys
from src.monitor import SecurityMonitor
from src.replay import new_freshness
from src.routed_peer import RoutedPeer, bootstrap_request, send_routed_message
from simulation.attacker import ATTACK_TYPES, AttackerPeer

RECENT_WINDOW = 5.0      # seconds used for the "recent" delivery rate
SAMPLE_PERIOD = 0.5      # seconds between samples of the overlay state
MAX_TRAFFIC_RATE = 15.0  # messages per second (stays below the flood limit)


# Default settings; the web page or a test can change any of them.
DEFAULTS = {
    "peers": 12,
    "attacker_ratio": 0.25,
    "monitor_on": True,
    "attack_types": list(ATTACK_TYPES),
    "drop_traffic": True,
    "outsider": True,
    "degree": 3,
    "traffic_rate": 6.0,
    "warmup": 6.0,
    "attack_interval": 2.0,
    "seed": None,
}


# Random connected overlay: a ring plus extra random links.
def build_topology(names, degree, rng):
    links = {name: set() for name in names}
    order = list(names)
    rng.shuffle(order)
    for index, name in enumerate(order):
        other = order[(index + 1) % len(order)]
        if other != name:
            links[name].add(other)
            links[other].add(name)
    for name in names:
        tries = 0
        while len(links[name]) < degree and tries < 50:
            tries += 1
            other = rng.choice(names)
            if other != name:
                links[name].add(other)
                links[other].add(name)
    return {name: sorted(neighbours) for name, neighbours in links.items()}


# One simulation run: start, sample, report, stop.
class Simulation:
    def __init__(self, **settings):
        unknown = set(settings) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"Unknown settings: {sorted(unknown)}")
        self.settings = dict(DEFAULTS, **settings)
        self._check_settings()
        self.rng = random.Random(self.settings["seed"])

        self.work_dir = None
        self.bootstrap = None
        self.peers = {}
        self.attackers = {}
        self.topology = {}
        self.honest = []

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads = []
        self.started_at = None
        self.stopped_at = None

        self.sent = 0
        self.delivered = 0
        self.outcomes = collections.deque()       # (time, delivered?)
        self.rtts = collections.deque(maxlen=500)
        self.hops = collections.deque(maxlen=500)
        self.recent_routes = collections.deque(maxlen=8)
        self.timeline = []                         # one row per second
        self.detected_at = {}                      # attacker -> seconds after its first attack
        self.flagged_honest = set()
        self.join_attempts = 0
        self.alerts = collections.deque(maxlen=60)
        self._alert_seen = {}

    def _check_settings(self):
        s = self.settings
        if not 4 <= int(s["peers"]) <= 60:
            raise ValueError("peers must be between 4 and 60")
        if not 0 <= float(s["attacker_ratio"]) <= 0.5:
            raise ValueError("attacker_ratio must be between 0 and 0.5")
        if not s["attack_types"] or set(s["attack_types"]) - set(ATTACK_TYPES):
            raise ValueError(f"attack_types must be taken from {ATTACK_TYPES}")
        s["peers"] = int(s["peers"])
        s["traffic_rate"] = min(float(s["traffic_rate"]), MAX_TRAFFIC_RATE)

    # ------------------------------------------------------------
    # Start and stop
    # ------------------------------------------------------------

    # Create keys, the bootstrap server and all peers, then start the workers.
    def start(self):
        s = self.settings
        self.work_dir = tempfile.mkdtemp(prefix="p2p_sim_")
        keys_dir = os.path.join(self.work_dir, "keys")
        self.keys_dir = keys_dir

        names = [f"P{index:02d}" for index in range(1, s["peers"] + 1)]
        generate_keys(names, keys_dir)

        count = round(s["peers"] * float(s["attacker_ratio"]))
        attacker_names = set(self.rng.sample(names, count))
        self.honest = [name for name in names if name not in attacker_names]
        self.topology = build_topology(names, int(s["degree"]), self.rng)

        self.bootstrap = BootstrapServer(
            host="127.0.0.1", port=0, verbose=False, keys_dir=keys_dir).start()
        self.bootstrap.monitor.alert_log = None
        self.bootstrap_address = ("127.0.0.1", self.bootstrap.port)

        types = list(s["attack_types"])
        for index, name in enumerate(names):
            options = dict(
                port=0, file_port=0, neighbours=self.topology[name],
                bind_host="127.0.0.1", advertised_host="127.0.0.1",
                bootstrap_address=self.bootstrap_address, socket_timeout=2.0,
                shared_folder=self.work_dir,
                received_folder=os.path.join(self.work_dir, "recv", name),
                verbose=False, keys_dir=keys_dir, monitor=self._monitor(name),
            )
            if name in attacker_names:
                peer = AttackerPeer(
                    name, attack=types[len(self.attackers) % len(types)],
                    drop_traffic=s["drop_traffic"], honest_peers=self.honest,
                    rng=random.Random(self.rng.random()), **options)
                self.attackers[name] = peer
            else:
                peer = RoutedPeer(name, **options)
            self.peers[name] = peer.start()

        self.started_at = time.time()
        self._spawn(self._sampler)
        for _ in range(4):
            self._spawn(self._traffic_worker)
        self._spawn(self._attack_loop)
        return self

    # A monitor per peer; with the monitor off nobody is ever quarantined.
    def _monitor(self, name):
        threshold = None if self.settings["monitor_on"] else -1.0
        return SecurityMonitor(name, threshold=threshold, verbose=False, alert_log=None)

    def _spawn(self, target):
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        self._threads.append(thread)

    # Stop the workers, the peers and the bootstrap server; delete the keys.
    def stop(self):
        if self._stop.is_set():
            return
        self._stop.set()
        self.stopped_at = time.time()
        for thread in self._threads:
            thread.join(timeout=5)
        for peer in self.peers.values():
            peer.stop()
        if self.bootstrap is not None:
            self.bootstrap.stop()
        if self.work_dir:
            shutil.rmtree(self.work_dir, ignore_errors=True)

    @property
    def running(self):
        return self.started_at is not None and not self._stop.is_set()

    def elapsed(self):
        if self.started_at is None:
            return 0.0
        return (self.stopped_at or time.time()) - self.started_at

    # ------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------

    # Honest traffic: random honest sender to random honest destination.
    def _traffic_worker(self):
        rng = random.Random(self.rng.random())
        pause = 4 / self.settings["traffic_rate"]
        while not self._stop.wait(pause * rng.uniform(0.5, 1.5)):
            if len(self.honest) < 2:
                continue
            sender, destination = rng.sample(self.honest, 2)
            ok, route = False, None
            try:
                result = send_routed_message(
                    sender, destination, "normal traffic",
                    bootstrap_address=self.bootstrap_address,
                    verbose=False, keys_dir=self.keys_dir)
                ok = result["status"] == "ok"
                route = result["route"]
            except Exception:
                pass
            with self._lock:
                self.sent += 1
                self.outcomes.append((time.time(), ok))
                if ok:
                    self.delivered += 1
                    self.rtts.append(result["rtt_ms"])
                    self.hops.append(result["hops"])
                    self.recent_routes.append({"route": route, "at": time.time()})

    # Attackers start after the warm-up and attack once per interval.
    def _attack_loop(self):
        s = self.settings
        if self._stop.wait(s["warmup"]):
            return
        for attacker in self.attackers.values():
            attacker.active = True
        while not self._stop.is_set():
            now = time.time()
            for attacker in self.attackers.values():
                try:
                    attacker.attack_round(now)
                except Exception:
                    pass
            if s["outsider"]:
                self._outsider_join()
            if self._stop.wait(s["attack_interval"]):
                return

    # An outsider without a key tries to join the overlay.
    def _outsider_join(self):
        try:
            bootstrap_request({
                "action": "register", "peer_id": "Intruder", "host": "127.0.0.1",
                "port": 1, "neighbours": [], "freshness": new_freshness(),
            }, self.bootstrap_address)
        except Exception:
            pass
        self.join_attempts += 1

    # Every half second: detections, alerts and one timeline row per second.
    def _sampler(self):
        last_row = -1
        while not self._stop.wait(SAMPLE_PERIOD):
            now = time.time()
            quarantined = self.quarantined()
            for name in quarantined:
                attacker = self.attackers.get(name)
                if attacker is not None:
                    if name not in self.detected_at and attacker.first_attack:
                        self.detected_at[name] = round(now - attacker.first_attack, 1)
                else:
                    self.flagged_honest.add(name)
            self._collect_alerts()

            second = int(now - self.started_at)
            if second != last_row:
                last_row = second
                with self._lock:
                    self.timeline.append({
                        "t": second,
                        "recent_delivery": self._recent_rate(now),
                        "sent": self.sent,
                        "delivered": self.delivered,
                        "quarantined": len(quarantined),
                        "attackers_detected": len(self.detected_at),
                    })

    def _collect_alerts(self):
        sources = [self.bootstrap.monitor] + [peer.monitor for peer in self.peers.values()]
        for monitor in sources:
            seen = self._alert_seen.get(monitor.owner, 0)
            lines = monitor.alerts[seen:]
            self._alert_seen[monitor.owner] = seen + len(lines)
            for line in lines:
                parts = line.split(" ", 2)
                text = f"{parts[1]} {parts[2]}" if len(parts) == 3 else line
                self.alerts.append(text.replace(" ALERT:", ""))

    # ------------------------------------------------------------
    # Results
    # ------------------------------------------------------------

    def _recent_rate(self, now):
        while self.outcomes and self.outcomes[0][0] < now - RECENT_WINDOW:
            self.outcomes.popleft()
        if not self.outcomes:
            return None
        return round(sum(ok for _, ok in self.outcomes) / len(self.outcomes), 3)

    # Peers quarantined by the bootstrap server or any honest peer.
    def quarantined(self):
        if not self.settings["monitor_on"] or self.bootstrap is None:
            return set()
        names = set(self.bootstrap.quarantined)
        for name in self.honest:
            names.update(q for q in self.peers[name].monitor.quarantined() if not q.startswith("ip:"))
        return names

    # Lowest trust any honest peer gives to each peer.
    def trust_scores(self):
        scores = {}
        for name in self.honest:
            for source, value in self.peers[name].monitor.report().items():
                if not source.startswith("ip:"):
                    scores[source] = min(value, scores.get(source, 1.0))
        return scores

    def summary(self):
        with self._lock:
            sent, delivered = self.sent, self.delivered
            rtts, hops = list(self.rtts), list(self.hops)
        times = list(self.detected_at.values())
        return {
            "sent": sent,
            "delivered": delivered,
            "delivery_rate": round(delivered / sent, 3) if sent else None,
            "recent_delivery": self._recent_rate(time.time()),
            "avg_rtt_ms": round(statistics.mean(rtts), 1) if rtts else None,
            "avg_hops": round(statistics.mean(hops), 2) if hops else None,
            "attackers": len(self.attackers),
            "detected": len(self.detected_at),
            "detection_rate": round(len(self.detected_at) / len(self.attackers), 3) if self.attackers else None,
            "mean_detection_s": round(statistics.mean(times), 1) if times else None,
            "false_positives": len(self.flagged_honest),
            "attack_messages": sum(a.attacks_sent for a in self.attackers.values()),
            "dropped_by_attackers": sum(a.dropped for a in self.attackers.values()),
            "join_attempts": self.join_attempts,
        }

    # Everything the web page needs in one snapshot.
    def state(self):
        quarantined = self.quarantined()
        trust = self.trust_scores()
        nodes = []
        for name, neighbours in self.topology.items():
            attacker = self.attackers.get(name)
            nodes.append({
                "id": name,
                "attacker": attacker is not None,
                "attack": attacker.attack if attacker else None,
                "active": bool(attacker and attacker.active),
                "quarantined": name in quarantined,
                "trust": trust.get(name, 1.0),
            })
        links = sorted({tuple(sorted((a, b))) for a, ns in self.topology.items() for b in ns})
        with self._lock:
            timeline = list(self.timeline)
            routes = [r["route"] for r in self.recent_routes if time.time() - r["at"] < 2.0]
        return {
            "running": self.running,
            "elapsed": round(self.elapsed(), 1),
            "phase": self._phase(),
            "settings": self.settings,
            "nodes": nodes,
            "links": [list(link) for link in links],
            "routes": routes,
            "summary": self.summary(),
            "detections": self.detected_at,
            "timeline": timeline,
            "alerts": list(self.alerts)[-25:],
        }

    def _phase(self):
        if not self.running:
            return "stopped"
        return "warm-up" if self.elapsed() < self.settings["warmup"] else "under attack"

    # Timeline as CSV text (for the report).
    def timeline_csv(self):
        rows = ["t,recent_delivery,sent,delivered,quarantined,attackers_detected"]
        with self._lock:
            for row in self.timeline:
                rows.append(",".join("" if row[k] is None else str(row[k]) for k in
                                     ("t", "recent_delivery", "sent", "delivered",
                                      "quarantined", "attackers_detected")))
        return "\n".join(rows) + "\n"


# Run one simulation without the web page and return its summary.
def run(duration=30.0, **settings):
    simulation = Simulation(**settings).start()
    try:
        time.sleep(duration)
        return simulation.summary()
    finally:
        simulation.stop()


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Run one simulation in the terminal")
    parser.add_argument("--peers", type=int, default=DEFAULTS["peers"])
    parser.add_argument("--attackers", type=float, default=DEFAULTS["attacker_ratio"])
    parser.add_argument("--monitor", choices=["on", "off"], default="on")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    print(json.dumps(run(args.duration, peers=args.peers, attacker_ratio=args.attackers,
                         monitor_on=args.monitor == "on", seed=args.seed), indent=2))
