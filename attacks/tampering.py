"""
New file: attack 4, message tampering.

Peer A sends "pay 10" to Peer D through Peer B. The message is changed
to "pay 1000" on the way, in two ways:
  1. by someone on the network without any key: the content is changed
     but the HMAC cannot be recomputed,
  2. by Peer B, a member that knows the shared HMAC key: the content is
     changed and the HMAC recomputed, but Peer A's signature cannot be.

Expected: Peer D drops every changed message; the HMAC check catches
case 1 and the signature check catches case 2. Peer B is blamed,
quarantined after a few attempts and avoided by the next message.

Run:  python -m attacks.tampering
"""

import json

from attacks.lab import AttackResult, run_script, short, wait_until
from src import config
from src.encryption import encrypt_content, message_context
from src.message import canonical_routed_message
from src.security import calculate_hmac

ROUTE = ["Peer A", "Peer B", "Peer D"]
INSIDER_ATTEMPTS = 3


# Change the content of a captured message; recompute the HMAC if the
# attacker knows the shared key.
def tamper(lab, line, knows_key):
    envelope = json.loads(line)
    envelope["content"] = encrypt_content(
        "pay 1000", lab.trust.encryption_key("Peer D"),
        message_context("Peer A", "Peer D", envelope["freshness"]["msg_id"]))
    if knows_key:
        original = canonical_routed_message(
            envelope["sender"], envelope["destination"], envelope["content"],
            envelope["route"], envelope["freshness"])
        envelope["tag"] = calculate_hmac(original, config.SECRET_KEY)
    return json.dumps(envelope).encode("utf-8") + b"\n"


# Change "pay 10" into "pay 1000" on the way to Peer D.
def run(lab):
    result = AttackResult("Message tampering",
                          "Change a message on its way (\"pay 10\" becomes \"pay 1000\")")
    outsider_reply = lab.send_raw(
        "Peer D", tamper(lab, lab.message("Peer A", "Peer D", ROUTE, "pay 10"), knows_key=False))
    insider_replies = [
        lab.send_raw("Peer D", tamper(lab, lab.message("Peer A", "Peer D", ROUTE, "pay 10"), knows_key=True))
        for _ in range(INSIDER_ATTEMPTS)]

    monitor = lab.peers["Peer D"].monitor
    reported = wait_until(lambda: "Peer B" in lab.quarantined_overlay())
    after = lab.honest_send("Peer A", "Peer D")
    alerts = lab.alerts("Peer D")
    hmac_alerts = [a for a in alerts if "bad_hmac" in a]
    signature_alerts = [a for a in alerts if "bad_signature from Peer B" in a or "QUARANTINED Peer B" in a]

    result.blocked = outsider_reply == b"" and not any(insider_replies)
    result.detected = bool(hmac_alerts) and bool(signature_alerts)
    if monitor.is_quarantined("Peer B") and reported and after.get("route") == ["Peer A", "Peer C", "Peer D"]:
        result.response = "Peer B quarantined and reported; traffic now goes A -> C -> D"
    result.evidence = [
        f"Changed without the key, accepted by Peer D: {bool(outsider_reply)} (HMAC check)",
        f"Changed by Peer B with the key, accepted: {sum(1 for r in insider_replies if r)} "
        f"of {INSIDER_ATTEMPTS} (signature check)",
        f"Peer B quarantined for the whole overlay: {reported}",
        f"Next honest message A -> D: {after['status']}, route {' -> '.join(after['route'] or [])}",
    ] + [short(a) for a in hmac_alerts[:1] + signature_alerts[:3]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
