"""
New file: attack 5, replay.

Peer B forwards a genuine message from Peer A to Peer D and keeps a
copy. It then sends an older captured message whose timestamp is two
minutes old, and the kept copy again (twice). Every copy still has a
valid HMAC and Peer A's valid signature.

Expected: the first, genuine delivery is accepted; every copy is
rejected (nonce already used, or timestamp outside the 30 s window).
Peer D blames Peer B, quarantines it, reports it, and the next message
is routed around B.

Run:  python -m attacks.replay_attack
"""

from attacks.lab import AttackResult, run_script, short, wait_until
from src.replay import new_freshness

ROUTE = ["Peer A", "Peer B", "Peer D"]
REPLAYS = 2
STALE_SECONDS = 120


# Peer B sends captured messages to Peer D again.
def run(lab):
    result = AttackResult("Replay",
                          "Send a captured, genuine message again")
    captured = lab.message("Peer A", "Peer D", ROUTE, "transfer 50")
    genuine = lab.send_raw("Peer D", captured)

    old = new_freshness()
    old["timestamp"] -= STALE_SECONDS * 1000
    stale = lab.send_raw("Peer D", lab.message("Peer A", "Peer D", ROUTE, "transfer 50", freshness=old))

    replays = [lab.send_raw("Peer D", captured) for _ in range(REPLAYS)]

    monitor = lab.peers["Peer D"].monitor
    reported = wait_until(lambda: "Peer B" in lab.quarantined_overlay())
    after = lab.honest_send("Peer A", "Peer D")
    alerts = [a for a in lab.alerts("Peer D") if "Peer B" in a]

    result.blocked = bool(genuine) and not any(replays) and stale == b""
    result.detected = any("replay from Peer B" in a for a in alerts)
    if monitor.is_quarantined("Peer B") and reported and after.get("route") == ["Peer A", "Peer C", "Peer D"]:
        result.response = "Peer B quarantined and reported; traffic now goes A -> C -> D"
    result.evidence = [
        f"Genuine first delivery accepted: {bool(genuine)}",
        f"Exact copies accepted: {sum(1 for r in replays if r)} of {REPLAYS}",
        f"Copy with a {STALE_SECONDS} s old timestamp accepted: {bool(stale)}",
        f"Peer B quarantined for the whole overlay: {reported}",
        f"Next honest message A -> D: {after['status']}, route {' -> '.join(after['route'] or [])}",
    ] + [short(a) for a in alerts[:4]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
