"""ITS overlay network, peer introduction, and local trust.

Manages the graph of ITS channels between nodes. Provides peer
introduction (Protocol 02) to establish new ITS channels without
depending on network topology. Computes local trust via personalized
PageRank on the channel graph (Protocol 06) for Sybil resistance.
"""

import math


class OverlayGraph:
    """Sparse adjacency representation of the ITS channel graph."""

    def __init__(self):
        self.adj: dict[int, set[int]] = {}
        self.weights: dict[tuple[int, int], float] = {}

    def add_node(self, node_id: int):
        if node_id not in self.adj:
            self.adj[node_id] = set()

    def add_edge(self, a: int, b: int, weight: float = 1.0):
        self.add_node(a)
        self.add_node(b)
        self.adj[a].add(b)
        self.adj[b].add(a)
        self.weights[(a, b)] = weight
        self.weights[(b, a)] = weight

    def remove_edge(self, a: int, b: int):
        self.adj[a].discard(b)
        self.adj[b].discard(a)
        self.weights.pop((a, b), None)
        self.weights.pop((b, a), None)

    def neighbors(self, node_id: int) -> set:
        return self.adj.get(node_id, set())

    def degree(self, node_id: int) -> int:
        return len(self.adj.get(node_id, set()))

    def out_weight(self, node_id: int) -> float:
        return sum(self.weights.get((node_id, n), 1.0) for n in self.adj.get(node_id, set()))

    @property
    def nodes(self) -> set:
        return set(self.adj.keys())

    @property
    def n_nodes(self) -> int:
        return len(self.adj)

    @property
    def n_edges(self) -> int:
        return sum(len(ns) for ns in self.adj.values()) // 2

    @classmethod
    def from_adjacency(cls, adj: dict) -> 'OverlayGraph':
        """Build from adjacency dict {node: set of neighbors}."""
        g = cls()
        for node, neighbors in adj.items():
            g.add_node(node)
            for n in neighbors:
                g.add_edge(node, n)
        return g


def personalized_pagerank(seed: int, graph: OverlayGraph,
                          d: float = 0.85, iterations: int = 20) -> dict:
    """Compute trust scores from seed's perspective.

    Uses power iteration on sparse adjacency.
    O(N * E * iterations) where E = edges per node on average.

    Args:
        seed: The node computing trust (personalization vector = unit at seed).
        graph: OverlayGraph with adjacency and weights.
        d: Damping factor (0.85 typical).
        iterations: Number of power iterations.

    Returns:
        Dict mapping node_id -> trust score. Sums to 1.0.
    """
    all_nodes = graph.nodes
    if not all_nodes:
        return {}

    # Initialize: all trust at seed
    trust = {n: 0.0 for n in all_nodes}
    trust[seed] = 1.0

    for _ in range(iterations):
        new_trust = {n: 0.0 for n in all_nodes}
        for u in all_nodes:
            out_w = graph.out_weight(u)
            if out_w == 0:
                continue
            for v in graph.neighbors(u):
                w = graph.weights.get((u, v), 1.0)
                new_trust[v] += d * trust[u] * w / out_w

        # Add teleport
        for n in all_nodes:
            teleport = (1 - d) if n == seed else 0.0
            new_trust[n] += teleport

        trust = new_trust

    return trust


def trust_weighted_accept(attestations: list, trust_scores: dict,
                          threshold: float = 2.0 / 3.0) -> bool:
    """Trust-weighted BFT acceptance.

    Args:
        attestations: List of node IDs that attested/signed.
        trust_scores: Dict from personalized_pagerank.
        threshold: Fraction of total trust required (default 2/3).

    Returns:
        True if attesting trust exceeds threshold.
    """
    total_trust = sum(trust_scores.values())
    if total_trust == 0:
        return False
    attesting_trust = sum(trust_scores.get(a, 0.0) for a in attestations)
    return attesting_trust > threshold * total_trust


class PeerIntroduction:
    """Multi-introducer PSK generation (Protocol 02).

    m introducers each generate a PSK component, sent over ITS channels.
    XOR combination produces the new pairwise PSK.
    """

    def __init__(self, graph: OverlayGraph, min_introducers: int = 3):
        self.graph = graph
        self.min_introducers = min_introducers

    def find_mutual_contacts(self, a: int, c: int) -> list:
        """Find nodes connected to both a and c."""
        return list(self.graph.neighbors(a) & self.graph.neighbors(c))

    def can_introduce(self, a: int, c: int) -> bool:
        """Check if enough mutual contacts exist for introduction."""
        return len(self.find_mutual_contacts(a, c)) >= self.min_introducers

    def generate_psk(self, components: list[bytes]) -> bytes:
        """XOR combine PSK components from introducers."""
        if not components:
            raise ValueError("Need at least one PSK component")
        result = bytearray(len(components[0]))
        for comp in components:
            for i in range(len(result)):
                result[i] ^= comp[i]
        return bytes(result)


class MutualContactFinder:
    """Identifies common neighbors for peer introductions."""

    def __init__(self, graph: OverlayGraph):
        self.graph = graph

    def find_for_pair(self, a: int, c: int, min_count: int = 3) -> list:
        """Find mutual contacts, sorted by combined trust/degree."""
        mutual = self.graph.neighbors(a) & self.graph.neighbors(c)
        # Sort by degree (higher degree = more connected = more reliable)
        return sorted(mutual, key=lambda n: -self.graph.degree(n))[:min_count * 2]


class GraphMonitor:
    """Monitors overlay graph health."""

    def __init__(self, graph: OverlayGraph):
        self.graph = graph

    def min_degree(self) -> int:
        if not self.graph.adj:
            return 0
        return min(self.graph.degree(n) for n in self.graph.nodes)

    def target_degree(self) -> int:
        """Target: ceil(log2(N)) + 1."""
        n = self.graph.n_nodes
        if n <= 1:
            return 0
        return max(3, math.ceil(math.log2(n)) + 1)

    def underconnected_nodes(self) -> list:
        """Nodes with degree below target."""
        target = self.target_degree()
        return [n for n in self.graph.nodes if self.graph.degree(n) < target]

    def is_connected(self) -> bool:
        if self.graph.n_nodes == 0:
            return True
        start = next(iter(self.graph.nodes))
        visited = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self.graph.neighbors(node) - visited)
        return len(visited) == self.graph.n_nodes
