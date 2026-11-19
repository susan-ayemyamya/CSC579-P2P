"""
New file: attack 6, flooding.

Peer C, a member, suddenly sends Peer D bursts of valid messages, many
more per second than any peer normally sends, to overload it.

Expected: Peer D keeps working (one thread per connection), detects
each flooded second (at least FLOOD_MIN_RATE messages and above the
3-sigma limit), quarantines Peer C after repeated floods and reports
it. Further flood messages are dropped and honest traffic from Peer A
still reaches Peer D, now around C.

Run:  python -m attacks.flooding
"""

import time

from attacks.lab import AttackResult, run_script, short, wait_until
from src import config

BURST = config.FLOOD_MIN_RATE + 10
BURSTS = 3


# Send one burst of valid messages from Peer C to Peer D within one second.
def burst(lab):
    time.sleep(1.0 - time.time() % 1.0 + 0.01)
    lines = [lab.message("Peer C", "Peer D", ["Peer C", "Peer D"], "flood") for _ in range(BURST)]
    return [lab.send_raw("Peer D", line) for line in lines]


# Peer C floods Peer D.
def run(lab):
    result = AttackResult("Flooding",
                          f"Overload a peer with bursts of {BURST} messages per second")
    replies = [burst(lab) for _ in range(BURSTS)]
    reported = wait_until(lambda: "Peer C" in lab.quarantined_overlay())
    after = lab.honest_send("Peer A", "Peer D")

    monitor = lab.peers["Peer D"].monitor
    alerts = [a for a in lab.alerts("Peer D") if "Peer C" in a]
    last_burst_accepted = sum(1 for r in replies[-1] if r)

    result.blocked = (monitor.is_quarantined("Peer C") and last_burst_accepted == 0
                      and after["status"] == "ok")
    result.detected = any("flood from Peer C" in a for a in alerts)
    if reported and after.get("route") == ["Peer A", "Peer B", "Peer D"]:
        result.response = "Peer C quarantined and reported; Peer D still serves honest traffic"
    result.evidence = [
        f"Messages accepted per burst: {[sum(1 for r in b if r) for b in replies]} (of {BURST})",
        f"Peer C's trust at Peer D: {monitor.trust('Peer C'):.2f} (quarantine below 0.60)",
        f"Peer C quarantined for the whole overlay: {reported}",
        f"Honest message A -> D afterwards: {after['status']}, route {' -> '.join(after['route'] or [])}",
    ] + [short(a) for a in alerts[:3]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
