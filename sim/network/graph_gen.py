"""Overlay topology generators.

Generates graph structures for the simulated Liun overlay network.
"""

import random
import math


def random_graph(n: int, channels_per_node: int = None, rng=None) -> dict:
    """Erdos-Renyi-like random graph with target degree.

    Returns adjacency dict: {node_id: set of neighbor_ids}.
    """
    if rng is None:
        rng = random.Random()
    if channels_per_node is None:
        channels_per_node = max(3, math.ceil(math.log2(n)) + 1)

    adj = {i: set() for i in range(n)}
    # Target number of edges
    target_edges = n * channels_per_node // 2
    nodes = list(range(n))

    edges_added = 0
    max_attempts = target_edges * 10
    attempts = 0
    while edges_added < target_edges and attempts < max_attempts:
        a = rng.choice(nodes)
        b = rng.choice(nodes)
        if a != b and b not in adj[a]:
            adj[a].add(b)
            adj[b].add(a)
            edges_added += 1
        attempts += 1

    return adj


def barabasi_albert(n: int, m: int = None, rng=None) -> dict:
    """Barabasi-Albert preferential attachment graph.

    Args:
        n: Number of nodes.
        m: Edges to add per new node (default: ceil(log2(n)/2)).
    """
    if rng is None:
        rng = random.Random()
    if m is None:
        m = max(2, math.ceil(math.log2(n) / 2))

    adj = {i: set() for i in range(n)}
    # Start with a complete graph on m+1 nodes
    for i in range(min(m + 1, n)):
        for j in range(i + 1, min(m + 1, n)):
            adj[i].add(j)
            adj[j].add(i)

    # Degree list for preferential attachment
    degree_list = []
    for i in range(min(m + 1, n)):
        degree_list.extend([i] * len(adj[i]))

    for new_node in range(m + 1, n):
        targets = set()
        while len(targets) < m and degree_list:
            target = rng.choice(degree_list)
            if target != new_node:
                targets.add(target)
        for t in targets:
            adj[new_node].add(t)
            adj[t].add(new_node)
            degree_list.extend([new_node, t])

    return adj


def small_world(n: int, k: int = None, p: float = 0.1, rng=None) -> dict:
    """Watts-Strogatz small-world graph.

    Args:
        n: Number of nodes.
        k: Each node connected to k nearest neighbors in ring (must be even).
        p: Rewiring probability.
    """
    if rng is None:
        rng = random.Random()
    if k is None:
        k = max(4, math.ceil(math.log2(n)))
        k = k + (k % 2)  # make even

    adj = {i: set() for i in range(n)}
    # Ring lattice
    for i in range(n):
        for j in range(1, k // 2 + 1):
            neighbor = (i + j) % n
            adj[i].add(neighbor)
            adj[neighbor].add(i)

    # Rewire
    for i in range(n):
        for j in range(1, k // 2 + 1):
            if rng.random() < p:
                neighbor = (i + j) % n
                if neighbor in adj[i] and len(adj[i]) > 1:
                    adj[i].discard(neighbor)
                    adj[neighbor].discard(i)
                    # Pick new target
                    candidates = [x for x in range(n)
                                  if x != i and x not in adj[i]]
                    if candidates:
                        new = rng.choice(candidates)
                        adj[i].add(new)
                        adj[new].add(i)

    return adj


def geographic(n: int, radius: float = None, rng=None) -> dict:
    """Random geometric graph: connect nodes within radius.

    Nodes placed uniformly in unit square.
    """
    if rng is None:
        rng = random.Random()
    if radius is None:
        # Choose radius to get ~log2(n) neighbors on average
        target_degree = max(3, math.ceil(math.log2(n)) + 1)
        radius = math.sqrt(target_degree / (n * math.pi))

    positions = [(rng.random(), rng.random()) for _ in range(n)]
    adj = {i: set() for i in range(n)}

    for i in range(n):
        for j in range(i + 1, n):
            dx = positions[i][0] - positions[j][0]
            dy = positions[i][1] - positions[j][1]
            if dx * dx + dy * dy <= radius * radius:
                adj[i].add(j)
                adj[j].add(i)

    return adj


def channels_per_node_default(n: int) -> int:
    """Default channels per node: max(3, ceil(log2(N)) + 1)."""
    return max(3, math.ceil(math.log2(n)) + 1)
