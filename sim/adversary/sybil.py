"""Sybil attack: fake node flooding + trust measurement.

Tests that personalized PageRank bounds Sybil influence
to O(g) where g is the number of attack edges.
"""

from liun.overlay import OverlayGraph, personalized_pagerank


class SybilAttack:
    """Simulates a Sybil attack on the overlay network.

    Eve creates S fake nodes densely connected to each other,
    with g attack edges connecting to honest nodes.
    """

    def __init__(self, honest_graph: OverlayGraph, n_sybil: int,
                 attack_edges: int, rng=None):
        self.honest_graph = honest_graph
        self.n_sybil = n_sybil
        self.attack_edges = attack_edges
        self.rng = rng

        self.honest_ids = set(honest_graph.nodes)
        self.sybil_ids = set()
        self.combined_graph = None

    def inject(self) -> OverlayGraph:
        """Inject Sybil nodes into the graph.

        Returns the combined graph with honest + sybil nodes.
        """
        import random
        rng = self.rng or random.Random(42)

        # Start with a copy of the honest graph
        g = OverlayGraph()
        for node in self.honest_graph.nodes:
            g.add_node(node)
        for node in self.honest_graph.nodes:
            for neighbor in self.honest_graph.neighbors(node):
                g.add_edge(node, neighbor)

        # Add sybil nodes
        base_id = max(self.honest_ids) + 1 if self.honest_ids else 0
        for i in range(self.n_sybil):
            sid = base_id + i
            self.sybil_ids.add(sid)
            g.add_node(sid)

        # Dense connections among sybils (sparse for large counts)
        sybil_list = sorted(self.sybil_ids)
        if len(sybil_list) <= 100:
            # Full clique for small counts
            for i in range(len(sybil_list)):
                for j in range(i + 1, len(sybil_list)):
                    g.add_edge(sybil_list[i], sybil_list[j])
        else:
            # Sparse but well-connected: ring + random shortcuts
            # Each sybil gets ~20 connections — enough for trust circulation
            k_internal = min(20, len(sybil_list) - 1)
            for i in range(len(sybil_list)):
                # Ring neighbors
                g.add_edge(sybil_list[i], sybil_list[(i + 1) % len(sybil_list)])
                # Random shortcuts
                targets = rng.sample(sybil_list, min(k_internal, len(sybil_list)))
                for t in targets:
                    if t != sybil_list[i]:
                        g.add_edge(sybil_list[i], t)

        # Attack edges: connect g sybils to g random honest nodes
        honest_list = sorted(self.honest_ids)
        n_edges = min(self.attack_edges, len(sybil_list), len(honest_list))
        honest_targets = rng.sample(honest_list, n_edges)
        for i in range(n_edges):
            g.add_edge(sybil_list[i], honest_targets[i])

        self.combined_graph = g
        return g

    def measure_trust_capture(self, seed: int) -> dict:
        """Measure trust captured by Sybil nodes from seed's perspective.

        Returns dict with trust metrics.
        """
        if self.combined_graph is None:
            self.inject()

        trust = personalized_pagerank(seed, self.combined_graph)

        honest_trust = sum(trust.get(n, 0) for n in self.honest_ids)
        sybil_trust = sum(trust.get(n, 0) for n in self.sybil_ids)
        total_trust = honest_trust + sybil_trust

        return {
            'honest_trust': honest_trust,
            'sybil_trust': sybil_trust,
            'total_trust': total_trust,
            'sybil_fraction': sybil_trust / total_trust if total_trust > 0 else 0,
            'sybil_equivalent_honest': sybil_trust / (honest_trust / len(self.honest_ids))
            if honest_trust > 0 else 0,
            'n_sybil': self.n_sybil,
            'attack_edges': self.attack_edges,
        }
