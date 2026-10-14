
class PeerDirectory:
    """Maintain a simple directory of known peers."""

    def __init__(self):
        self._peers = {}

    def register(self, peer_id, host, port):
        """Register a peer or update its address."""
        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("Peer ID must be a non-empty string")

        if not isinstance(host, str) or not host.strip():
            raise ValueError("Host must be a non-empty string")

        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("Port must be an integer")

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")

        self._peers[peer_id] = {
            "peer_id": peer_id,
            "host": host,
            "port": port,
        }

    def get_peers(self, exclude_peer_id=None):
        """Return known peers, optionally excluding one peer."""
        return [
            peer.copy()
            for peer_id, peer in sorted(self._peers.items())
            if peer_id != exclude_peer_id
        ]

    def unregister(self, peer_id):
        """Remove a peer from the directory."""
        self._peers.pop(peer_id, None)
