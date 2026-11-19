"""
New file: attack 1, unauthorized peer.

Mallory is not a member of the overlay: her key is not in the trusted
list. In the worst case she even knows the shared HMAC key. She tries to
  1. join with a registration signed by her own key,
  2. join with an unsigned registration,
  3. send a message straight to Peer A.

Expected: both joins are refused and raise alerts at the bootstrap
server, Mallory never appears in the peer list, and Peer A drops her
message (signature check) and lowers her trust.

Run:  python -m attacks.unauthorized_peer
"""

from attacks.lab import OUTSIDER, AttackResult, run_script, short
from src.identity import sign_request
from src.replay import new_freshness


# Mallory tries to join and to talk to Peer A.
def run(lab):
    result = AttackResult("Unauthorized peer",
                          "An outsider without a trusted key joins and sends messages")
    registration = {"action": "register", "peer_id": OUTSIDER, "host": "127.0.0.1",
                    "port": 6666, "file_port": 6766, "neighbours": ["Peer A"]}

    signed = lab.bootstrap_call(sign_request(dict(registration, freshness=new_freshness()),
                                             lab.identity(OUTSIDER)))
    unsigned = lab.bootstrap_call(dict(registration, freshness=new_freshness()))
    reply = lab.send_raw("Peer A", lab.message(OUTSIDER, "Peer A", [OUTSIDER, "Peer A"]))

    in_directory = OUTSIDER in lab.directory()
    join_alerts = [a for a in lab.alerts("Bootstrap") if "unauthorized_join from" in a]
    peer_alerts = [a for a in lab.alerts("Peer A") if OUTSIDER in a]

    result.blocked = (signed["status"] == "error" and unsigned["status"] == "error"
                      and not in_directory and reply == b"")
    result.detected = len(join_alerts) >= 2 and bool(peer_alerts)
    result.response = "Join refused; message dropped; outsider never listed"
    result.evidence = [
        f"Join signed with untrusted key: {signed['status']} ({signed.get('message', '')})",
        f"Join without signature: {unsigned['status']} ({unsigned.get('message', '')})",
        f"Mallory in the peer list: {in_directory}",
        f"Message to Peer A answered: {bool(reply)}",
    ] + [short(a) for a in join_alerts[:2] + peer_alerts[:1]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
