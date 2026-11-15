'''
Modifications (branch overlay-improvements)
   1. register() and get_peers() also store each peer's file port and
      its list of overlay neighbours.
      Why: routes are now computed from the directory instead of
      hand-written tables. This is needed for many peers (simulation)
      and for routing around a quarantined peer (Step 6).

   2. New helpers _validate_port() and _validate_neighbours().
      Why: a peer now has two ports that must be checked the same way,
      and neighbour lists arrive from the network, so they are checked
      before they are stored and used for routing.

'''

# Check that a value is a valid TCP port number.
def _validate_port(port, name="Port"):
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"{name} must be an integer")

    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")


class PeerDirectory:
    """Maintain a simple directory of known peers."""

    def __init__(self):
        self._peers = {}

    # Register a peer or update its address.
    def register(self, peer_id, host, port, file_port=None, neighbours=None):
        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("Peer ID must be a non-empty string")

        if not isinstance(host, str) or not host.strip():
            raise ValueError("Host must be a non-empty string")

        _validate_port(port)

        if file_port is not None:
            _validate_port(file_port, "File port")

        self._peers[peer_id] = {
            "peer_id": peer_id,
            "host": host,
            "port": port,
            "file_port": file_port,
            "neighbours": self._validate_neighbours(peer_id, neighbours),
        }

    # Return known peers, optionally excluding one peer.
    def get_peers(self, exclude_peer_id=None):
        return [
            {**peer, "neighbours": list(peer["neighbours"])}
            for peer_id, peer in sorted(self._peers.items())
            if peer_id != exclude_peer_id
        ]

    def unregister(self, peer_id):
        """Remove a peer from the directory."""
        self._peers.pop(peer_id, None)

    # Check the list of neighbour IDs a peer registers with.
    @staticmethod
    def _validate_neighbours(peer_id, neighbours):
        if neighbours is None:
            return []

        if not isinstance(neighbours, list):
            raise ValueError("Neighbours must be a list")

        for neighbour_id in neighbours:
            if not isinstance(neighbour_id, str) or not neighbour_id.strip():
                raise ValueError("Neighbour ID must be a non-empty string")

            if neighbour_id == peer_id:
                raise ValueError("A peer cannot be its own neighbour")

        return list(dict.fromkeys(neighbours))
