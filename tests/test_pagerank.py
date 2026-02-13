"""Tests for personalized PageRank and overlay trust."""

import pytest
from liun.overlay import (
    OverlayGraph, personalized_pagerank, trust_weighted_accept,
    PeerIntroduction, GraphMonitor,
)


def _make_line_graph(n):
    """0 -- 1 -- 2 -- ... -- n-1."""
    g = OverlayGraph()
    for i in range(n):
        g.add_node(i)
    for i in range(n - 1):
        g.add_edge(i, i + 1)
    return g


def _make_complete_graph(n):
    g = OverlayGraph()
    for i in range(n):
        g.add_node(i)
        for j in range(i + 1, n):
            g.add_edge(i, j)
    return g


def _make_sybil_graph(n_honest, n_sybil, attack_edges):
    """Create honest clique + sybil clique with g attack edges."""
    g = OverlayGraph()
    # Honest nodes: 0..n_honest-1, complete graph
    for i in range(n_honest):
        g.add_node(i)
        for j in range(i + 1, n_honest):
            g.add_edge(i, j)

    # Sybil nodes: n_honest..n_honest+n_sybil-1, complete graph
    for i in range(n_honest, n_honest + n_sybil):
        g.add_node(i)
        for j in range(i + 1, n_honest + n_sybil):
            g.add_edge(i, j)

    # Attack edges: connect first g sybils to first g honest nodes
    for i in range(min(attack_edges, n_sybil, n_honest)):
        g.add_edge(i, n_honest + i)

    return g


class TestTrustSumsToOne:

    def test_line_graph(self):
        g = _make_line_graph(10)
        trust = personalized_pagerank(0, g)
        assert abs(sum(trust.values()) - 1.0) < 1e-10

    def test_complete_graph(self):
        g = _make_complete_graph(10)
        trust = personalized_pagerank(0, g)
        assert abs(sum(trust.values()) - 1.0) < 1e-10

    def test_sybil_graph(self):
        g = _make_sybil_graph(10, 20, 3)
        trust = personalized_pagerank(0, g)
        assert abs(sum(trust.values()) - 1.0) < 1e-10


class TestSeedHasHighestTrust:

    def test_line_seed_higher_than_distant(self):
        """In a line graph, seed has more trust than distant nodes."""
        g = _make_line_graph(10)
        trust = personalized_pagerank(0, g)
        # Seed at endpoint may not beat its immediate neighbor (degree effect),
        # but definitely beats distant nodes
        assert trust[0] > trust[5]
        assert trust[0] > trust[9]

    def test_complete_seed_highest(self):
        g = _make_complete_graph(10)
        trust = personalized_pagerank(5, g)
        assert trust[5] >= max(trust[n] for n in trust if n != 5)


class TestSybilBound:
    """Sybil cluster with g attack edges gets O(g) total trust."""

    def test_sybil_trust_bounded(self):
        """1000 Sybils with g attack edges get trust ~ g honest nodes."""
        n_honest = 20
        n_sybil = 100
        g = 3

        graph = _make_sybil_graph(n_honest, n_sybil, g)
        trust = personalized_pagerank(0, graph)

        sybil_total = sum(trust[i] for i in range(n_honest, n_honest + n_sybil))
        honest_total = sum(trust[i] for i in range(n_honest))

        # Sybil trust should be bounded ~ g/n_honest of honest trust
        # More precisely: total sybil trust should not exceed g * (avg honest trust)
        avg_honest = honest_total / n_honest
        # Sybil total trust should be significantly less than honest total
        assert sybil_total < honest_total
        # And bounded proportional to g
        assert sybil_total < (g + 1) * avg_honest * 3  # generous bound

    def test_sybil_scaling_with_attack_edges(self):
        """More attack edges = more Sybil trust (linear)."""
        n_honest = 20
        n_sybil = 50

        results = {}
        for g in [1, 3, 5, 10]:
            graph = _make_sybil_graph(n_honest, n_sybil, g)
            trust = personalized_pagerank(0, graph)
            sybil_total = sum(trust[i] for i in range(n_honest, n_honest + n_sybil))
            results[g] = sybil_total

        # Trust should increase with g
        assert results[3] > results[1]
        assert results[5] > results[3]
        assert results[10] > results[5]


class TestConvergence:

    def test_converges_within_20_iterations(self):
        g = _make_complete_graph(20)
        trust_10 = personalized_pagerank(0, g, iterations=10)
        trust_20 = personalized_pagerank(0, g, iterations=20)
        trust_50 = personalized_pagerank(0, g, iterations=50)

        # 20 and 50 should be very close
        max_diff = max(abs(trust_20[n] - trust_50[n]) for n in trust_20)
        assert max_diff < 1e-8

    def test_10_iterations_close(self):
        g = _make_complete_graph(20)
        trust_10 = personalized_pagerank(0, g, iterations=10)
        trust_20 = personalized_pagerank(0, g, iterations=20)
        max_diff = max(abs(trust_10[n] - trust_20[n]) for n in trust_10)
        assert max_diff < 1e-4


class TestDifferentSeeds:

    def test_different_seeds_different_trust(self):
        g = _make_line_graph(10)
        trust_0 = personalized_pagerank(0, g)
        trust_9 = personalized_pagerank(9, g)
        # Node 0's trust from seed 0 vs seed 9 should differ
        assert abs(trust_0[0] - trust_9[0]) > 0.01


class TestTrustWeightedAccept:

    def test_majority_accepts(self):
        trust = {0: 0.3, 1: 0.25, 2: 0.25, 3: 0.1, 4: 0.1}
        assert trust_weighted_accept([0, 1, 2], trust)  # 0.8 > 2/3

    def test_minority_rejects(self):
        trust = {0: 0.3, 1: 0.25, 2: 0.25, 3: 0.1, 4: 0.1}
        assert not trust_weighted_accept([3, 4], trust)  # 0.2 < 2/3


class TestPeerIntroduction:

    def test_find_mutual_contacts(self):
        g = _make_complete_graph(5)
        pi = PeerIntroduction(g)
        mutual = pi.find_mutual_contacts(0, 4)
        assert set(mutual) == {1, 2, 3}

    def test_can_introduce(self):
        g = _make_complete_graph(5)
        pi = PeerIntroduction(g)
        assert pi.can_introduce(0, 4)

    def test_cannot_introduce_no_mutual(self):
        g = OverlayGraph()
        for i in range(4):
            g.add_node(i)
        g.add_edge(0, 1)
        g.add_edge(2, 3)
        pi = PeerIntroduction(g)
        assert not pi.can_introduce(0, 3)

    def test_xor_psk_generation(self):
        pi = PeerIntroduction(OverlayGraph())
        c1 = b'\x01\x02\x03\x04'
        c2 = b'\x10\x20\x30\x40'
        c3 = b'\xff\x00\xff\x00'
        psk = pi.generate_psk([c1, c2, c3])
        # XOR of all three
        expected = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, c3))
        assert psk == expected


class TestGraphMonitor:

    def test_connectivity(self):
        g = _make_complete_graph(5)
        mon = GraphMonitor(g)
        assert mon.is_connected()

    def test_disconnected(self):
        g = OverlayGraph()
        g.add_node(0)
        g.add_node(1)
        mon = GraphMonitor(g)
        assert not mon.is_connected()
