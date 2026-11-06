
def get_next_hop(destination, routing_table):
    """
    Find the next peer to forward a message to.

    routing_table maps a destination peer ID
    to the immediate next-hop peer ID.
    """

    if not isinstance(destination, str) or not destination.strip():
        raise ValueError("Destination must be a non-empty string")

    if not isinstance(routing_table, dict):
        raise ValueError("Routing table must be a dictionary")

    next_hop = routing_table.get(destination)

    if next_hop is None:
        return None

    if not isinstance(next_hop, str) or not next_hop.strip():
        raise ValueError("Next-hop peer ID must be a non-empty string")

    return next_hop
