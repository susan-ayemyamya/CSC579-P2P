"""
New file: security monitor (attack detection and response).

Ideas taken from TruChord:
  - trust score per source between 0 and 1, starting at 1.0
  - every bad event lowers the score (penalties in config.PENALTIES)
  - time decay: a penalty is multiplied by TRUST_DECAY (0.9) for every
    DECAY_PERIOD seconds that pass, so a single old mistake fades away,
    while repeated attacks keep the score low (on-off attacks)
  - 3-sigma filter: a message rate far above a source's normal rate
    is a flood
  - quarantine: a source whose score drops below TRUST_THRESHOLD (0.6)
    is quarantined and an alert is written

Example (from the project mapping): a peer starts at 1.0, two failed
HMAC checks (-0.2 each) and one replay (-0.3) bring it to 0.3, which is
below 0.6, so it is quarantined.

A "source" is a peer ID, or "ip:<address>" for traffic that could not
be linked to any peer (for example messages without a valid HMAC).
"""

import os
import statistics
import threading
import time
from collections import defaultdict, deque

from src import config

HISTORY_WINDOWS = 30   # seconds of normal-rate history kept per source
MIN_HISTORY = 5        # windows needed before the 3-sigma rule is used


# Tracks trust, detects floods and quarantines misbehaving sources.
class SecurityMonitor:

    def __init__(
        self,
        owner,
        threshold=None,
        decay=None,
        decay_period=None,
        penalties=None,
        flood_min_rate=None,
        alert_log=None,
        on_quarantine=None,
        clock=time.time,
        verbose=True,
    ):
        self.owner = owner
        self.threshold = config.TRUST_THRESHOLD if threshold is None else threshold
        self.decay = config.TRUST_DECAY if decay is None else decay
        self.decay_period = config.DECAY_PERIOD if decay_period is None else decay_period
        self.penalties = dict(config.PENALTIES if penalties is None else penalties)
        self.flood_min_rate = config.FLOOD_MIN_RATE if flood_min_rate is None else flood_min_rate
        self.alert_log = alert_log
        self.on_quarantine = on_quarantine
        self.clock = clock
        self.verbose = verbose

        self._events = defaultdict(list)          # source -> [(time, penalty, event)]
        self._quarantined = {}                    # source -> reason
        self._window = {}                         # source -> (second, count)
        self._history = defaultdict(lambda: deque(maxlen=HISTORY_WINDOWS))
        self._flooded = set()                     # (source, second) already reported
        self.alerts = []                          # alert lines (also used by tests)
        self._lock = threading.Lock()

    # ------------------------------------------------------------
    # Trust
    # ------------------------------------------------------------

    # Current trust of a source: 1.0 minus its decayed penalties.
    #   Each penalty counts as penalty * decay ** (age / decay_period),
    #   so recent events weigh more than old ones.
    def trust(self, source):
        with self._lock:
            return self._trust(source, self.clock())

    def _trust(self, source, now):
        total = 0.0
        for when, penalty, _ in self._events.get(source, []):
            age = max(0.0, now - when)
            total += penalty * self.decay ** (age / self.decay_period)
        return max(0.0, 1.0 - total)

    # Record one bad event for a source and react to it.
    #   1. Add the event's penalty with the current time.
    #   2. Recompute the trust score.
    #   3. If it falls below the threshold, quarantine the source.
    # Returns the new trust score.
    def record(self, source, event, detail=""):
        penalty = self.penalties.get(event, 0.1)

        with self._lock:
            now = self.clock()
            self._events[source].append((now, penalty, event))
            score = self._trust(source, now)
            newly_quarantined = (
                score < self.threshold and source not in self._quarantined
            )
            if newly_quarantined:
                self._quarantined[source] = event

        self._alert(f"{event} from {source} (trust {score:.2f})"
                    + (f": {detail}" if detail else ""))

        if newly_quarantined:
            self._alert(f"QUARANTINED {source}: trust {score:.2f} below "
                        f"{self.threshold:.2f} (last event: {event})")
            if self.on_quarantine is not None:
                try:
                    self.on_quarantine(source, event)
                except Exception as error:
                    self._alert(f"Could not report {source}: {error}")

        return score

    # ------------------------------------------------------------
    # Flood detection (3-sigma rule)
    # ------------------------------------------------------------

    # Count one message from a source and check for a flood.
    #   1. Messages are counted per one-second window.
    #   2. When a window ends, its count becomes part of the history.
    #   3. A window is a flood if its count is at least flood_min_rate
    #      and (with enough history) above mean + 3 * standard deviation.
    # Returns True if this message made the window a flood.
    def observe(self, source):
        with self._lock:
            now = self.clock()
            second = int(now)
            window_second, count = self._window.get(source, (second, 0))

            if window_second != second:
                # Close the old window (and empty seconds in between).
                history = self._history[source]
                history.append(count)
                for _ in range(min(second - window_second - 1, HISTORY_WINDOWS)):
                    history.append(0)
                count = 0

            count += 1
            self._window[source] = (second, count)
            is_flood = self._is_flood(source, count) and (source, second) not in self._flooded
            if is_flood:
                self._flooded.add((source, second))

        if is_flood:
            self.record(source, "flood", f"{count} messages in one second")

        return is_flood

    def _is_flood(self, source, count):
        if count < self.flood_min_rate:
            return False

        history = list(self._history[source])
        if len(history) < MIN_HISTORY:
            return True

        mean = statistics.mean(history)
        spread = statistics.pstdev(history)
        return count > mean + 3 * spread

    # ------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------

    # Is this source quarantined?
    def is_quarantined(self, source):
        with self._lock:
            return source in self._quarantined

    # All quarantined sources.
    def quarantined(self):
        with self._lock:
            return sorted(self._quarantined)

    # Take a source out of quarantine and forget its events (manual).
    def release(self, source):
        with self._lock:
            self._quarantined.pop(source, None)
            self._events.pop(source, None)
        self._alert(f"Released {source} from quarantine")

    # Trust score of every source seen so far.
    def report(self):
        with self._lock:
            now = self.clock()
            return {source: round(self._trust(source, now), 3) for source in self._events}

    # ------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------

    # Write an alert to the screen, the alert list and the log file.
    def _alert(self, text):
        line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{self.owner}] ALERT: {text}")
        self.alerts.append(line)

        if self.verbose:
            print(line)

        if self.alert_log:
            try:
                os.makedirs(os.path.dirname(self.alert_log) or ".", exist_ok=True)
                with open(self.alert_log, "a", encoding="utf-8") as file:
                    file.write(line + "\n")
            except OSError:
                pass


# Default alert log path for a peer, e.g. alerts/Peer_A.log
def alert_log_path(owner):
    return os.path.join(config.ALERTS_DIR, owner.replace(" ", "_") + ".log")
