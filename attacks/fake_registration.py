"""
New file: attack 2, fake registration.

Peer C is a member, but tries to hijack Peer B's identity at the
bootstrap server so that traffic for Peer B is sent to C's address:
  1. registers as "Peer B" with its own address, signed with C's key,
  2. resends a genuine registration of Peer B that it captured earlier,
     with its own address put in (the signature no longer matches),
  3. resends the captured registration unchanged (a replay).

Expected: all three are refused, each raises an alert at the bootstrap
server, and Peer B's address in the peer list stays the real one.

Run:  python -m attacks.fake_registration
"""

from attacks.lab import AttackResult, run_script, short
from src.identity import sign_request
from src.replay import new_freshness


# Peer C tries to register under Peer B's name.
def run(lab):
    result = AttackResult("Fake registration",
                          "A member registers under another peer's name to steal its traffic")
    real_port = lab.directory()["Peer B"]["port"]
    attacker_port = lab.peers["Peer C"].port
    fake = {"action": "register", "peer_id": "Peer B", "host": "127.0.0.1",
            "port": attacker_port, "file_port": 0, "neighbours": ["Peer A", "Peer D"]}

    forged = lab.bootstrap_call(sign_request(dict(fake, freshness=new_freshness()),
                                             lab.identity("Peer C")))

    # A genuine registration of Peer B, as captured on the network.
    captured = sign_request({
        "action": "register", "peer_id": "Peer B", "host": "127.0.0.1", "port": real_port,
        "file_port": lab.peers["Peer B"].file_port, "neighbours": ["Peer A", "Peer D"],
        "freshness": new_freshness()}, lab.identity("Peer B"))
    original = lab.bootstrap_call(captured)          # the real one, as Peer B sent it
    edited = lab.bootstrap_call(dict(captured, port=attacker_port))
    replayed = lab.bootstrap_call(captured)

    port_now = lab.directory()["Peer B"]["port"]
    join_alerts = [a for a in lab.alerts("Bootstrap") if "unauthorized_join from" in a]

    result.blocked = (forged["status"] == edited["status"] == replayed["status"] == "error"
                      and original["status"] == "ok" and port_now == real_port)
    result.detected = len(join_alerts) >= 3
    result.response = "All three refused; Peer B keeps its real address"
    result.evidence = [
        f"Registered as Peer B with Peer C's key: {forged['status']} ({forged.get('message', '')})",
        f"Captured registration with changed address: {edited['status']} ({edited.get('message', '')})",
        f"Captured registration replayed: {replayed['status']} ({replayed.get('message', '')})",
        f"Peer B's port in the peer list: {port_now} (real port {real_port})",
    ] + [short(a) for a in join_alerts[:3]]
    return result


if __name__ == "__main__":
    raise SystemExit(run_script(run))
