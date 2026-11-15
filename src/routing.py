'''
Modifications (branch overlay-improvements)
   1. get_next_hop() is unchanged.

   2. New build_graph(), shortest_path() and build_routing_table().
      Why: routing tables were written by hand for A -> B -> C only.
      These build routes for any number of peers from the neighbour
      links registered with the bootstrap server (needed for the
      simulation in Step 8). build_routing_table() returns tables in
      the same format as before.

   3. shortest_path() takes an 'excluded' set of peers.
      Why: traffic must be able to avoid a peer that the security
      monitor has quarantined (Step 6) and still find another route.

'''

from collections import deque


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


# Build an undirected overlay graph from bootstrap peer records.
#
# Each record has "peer_id" and "neighbours" (a list of peer IDs).
# A link exists if either side lists the other. Links to peers
# that are not registered are ignored.
#
# Returns {peer_id: set of neighbour IDs}.
def build_graph(peers):
    graph = {}

    for peer in peers:
        peer_id = peer.get("peer_id")

        if isinstance(peer_id, str) and peer_id.strip():
            graph.setdefault(peer_id, set())

    for peer in peers:
        peer_id = peer.get("peer_id")

        if peer_id not in graph:
            continue

        for neighbour_id in peer.get("neighbours") or []:
            if neighbour_id in graph and neighbour_id != peer_id:
                graph[peer_id].add(neighbour_id)
                graph[neighbour_id].add(peer_id)

    return graph


# Find the route with the fewest hops from source to destination.
#
# excluded is a set of peer IDs that must not be used.
# Returns the route as a list of peer IDs, or None if no route exists.
def shortest_path(graph, source, destination, excluded=None):
    excluded = set(excluded or ())

    if source not in graph or destination not in graph:
        return None

    if source in excluded or destination in excluded:
        return None

    previous = {source: None}
    queue = deque([source])

    while queue:
        peer_id = queue.popleft()

        if peer_id == destination:
            break

        # Sort neighbours so equal-length routes are chosen consistently.
        for neighbour_id in sorted(graph[peer_id]):
            if neighbour_id in excluded or neighbour_id in previous:
                continue

            previous[neighbour_id] = peer_id
            queue.append(neighbour_id)

    if destination not in previous:
        return None

    route = [destination]

    while route[-1] != source:
        route.append(previous[route[-1]])

    route.reverse()
    return route


# Build a next-hop routing table for one peer.
#
# Returns {destination: next_hop} for every reachable peer, in the
# same format that get_next_hop() uses.
def build_routing_table(graph, source, excluded=None):
    table = {}

    for destination in sorted(graph):
        if destination == source:
            continue

        route = shortest_path(graph, source, destination, excluded)

        if route is not None and len(route) >= 2:
            table[destination] = route[1]

    return table
