"""
New file: attack 3, impersonation.

Peer B is a member and sits between Peer A and Peer D. It sends
messages to Peer D that claim to come from Peer A, for example
"Peer A says: pay 1000". B knows the shared HMAC key, so the HMAC is
valid, but B can only sign with its own key.

Expected: Peer D rejects every message (the signature is not Peer A's),
blames Peer B (the neighbour that delivered it), quarantines B after a
few attempts and reports it, and Peer A's next message to Peer D is
routed around B (through Peer C).

Run:  python -m attacks.impersonation
"""

from attacks.lab import AttackResult, run_script, short, wait_until

ATTEMPTS = 3


# Peer B pretends to be Peer A.
def run(lab):
    result = AttackResult("Impersonation",
                          "A member sends messages in another peer's name")
    replies = []
    for _ in range(ATTEMPTS):
        fake = lab.message("Peer A", "Peer D", ["Peer A", "Peer B", "Peer D"],
                           text="Peer A says: pay 1000", signer=lab.identity("Peer B"))
        replies.append(lab.send_raw("Peer D", fake))

    monitor = lab.peers["Peer D"].monitor
    reported = wait_until(lambda: "Peer B" in lab.quarantined_overlay())
    after = lab.honest_send("Peer A", "Peer D")
    alerts = [a for a in lab.alerts("Peer D") if "Peer B" in a]

    result.blocked = not any(replies)
    result.detected = any("bad_signature" in a for a in alerts)
    if monitor.is_quarantined("Peer B") and reported and after.get("route") == ["Peer A", "Peer C", "Peer D"]:
        result.response = "Peer B quarantined and reported; traffic now goes A -> C -> D"
    result.evidence = [
        f"Fake messages accepted by Peer D: {sum(1 for r in replies if r)} of {ATTEMPTS}",
        f"Peer B's trust at Peer D: {monitor.trust('Peer B'):.2f} (quarantine below 0.60)",
        f"Peer B quarantined for the whole overlay: {reported}",
        f"Next honest message A -> D: {after['status']}, route {' -> '.join(after['route'] or [])}",
    ] + [short(a) for a in alerts[:4]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
