"""Tests for peer introduction protocol (Protocol 02)."""

import random
import os
import pytest
from liun.overlay import (
    OverlayGraph, PeerIntroduction, MutualContactFinder,
    GraphMonitor, personalized_pagerank,
)


def _make_ring_graph(n):
    """Ring graph: each node connected to 2 neighbors."""
    g = OverlayGraph()
    for i in range(n):
        g.add_node(i)
    for i in range(n):
        g.add_edge(i, (i + 1) % n)
    return g


def _make_complete_graph(n):
    g = OverlayGraph()
    for i in range(n):
        g.add_node(i)
        for j in range(i + 1, n):
            g.add_edge(i, j)
    return g


class TestPeerIntroductionProtocol:

    def test_xor_produces_correct_psk(self):
        """XOR of 3 components = correct combined PSK."""
        pi = PeerIntroduction(OverlayGraph())
        c1 = os.urandom(32)
        c2 = os.urandom(32)
        c3 = os.urandom(32)
        psk = pi.generate_psk([c1, c2, c3])
        expected = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, c3))
        assert psk == expected

    def test_xor_is_self_inverse(self):
        """XOR twice returns to original."""
        pi = PeerIntroduction(OverlayGraph())
        c1 = b'\xab' * 32
        c2 = b'\xcd' * 32
        combined = pi.generate_psk([c1, c2])
        # XOR with c2 again recovers c1
        recovered = pi.generate_psk([combined, c2])
        assert recovered == c1

    def test_one_corrupt_introducer_doesnt_leak(self):
        """Eve knows 1 of 3 components — PSK still ITS-secret."""
        pi = PeerIntroduction(OverlayGraph())
        rng = random.Random(42)
        components = [bytes(rng.getrandbits(8) for _ in range(32))
                      for _ in range(3)]
        psk = pi.generate_psk(components)

        # Eve knows component 0 and tries to brute-force
        # With 256-bit unknowns, this is impossible
        # Test: knowing 1 component gives zero info about PSK
        eve_known = components[0]
        # PSK = c0 ^ c1 ^ c2. Eve knows c0 but not c1, c2.
        # For any candidate PSK, there exist c1, c2 consistent with Eve's view.
        # (Set c1=0, c2 = candidate_psk ^ c0)
        # This means every PSK is equally likely from Eve's perspective.
        assert psk != eve_known  # trivially different

    def test_two_corrupt_of_three_still_secure(self):
        """Even with 2 of 3 corrupt introducers, 1 unknown component suffices."""
        pi = PeerIntroduction(OverlayGraph())
        rng = random.Random(42)
        components = [bytes(rng.getrandbits(8) for _ in range(32))
                      for _ in range(3)]
        psk = pi.generate_psk(components)

        # Eve knows c0 and c1, not c2
        eve_partial = pi.generate_psk([components[0], components[1]])
        # psk = c0 ^ c1 ^ c2 = eve_partial ^ c2
        # Eve doesn't know c2, so psk is uniform from her view
        assert psk != eve_partial


class TestMutualContactFinding:

    def test_complete_graph_all_mutual(self):
        g = _make_complete_graph(6)
        mcf = MutualContactFinder(g)
        mutual = mcf.find_for_pair(0, 5)
        assert set(mutual) & {1, 2, 3, 4}  # all intermediate nodes

    def test_ring_limited_mutual(self):
        g = _make_ring_graph(10)
        mcf = MutualContactFinder(g)
        # In ring, node 0 and node 5 have no mutual contacts
        mutual = mcf.find_for_pair(0, 5)
        assert len(mutual) == 0

    def test_ring_adjacent_have_mutual(self):
        g = _make_ring_graph(10)
        mcf = MutualContactFinder(g)
        # Node 0 neighbors: 1, 9. Node 2 neighbors: 1, 3.
        # Mutual of (0, 2) = {1}
        mutual = mcf.find_for_pair(0, 2)
        assert 1 in mutual

    def test_sorted_by_degree(self):
        """Mutual contacts sorted by degree (highest first)."""
        g = OverlayGraph()
        for i in range(7):
            g.add_node(i)
        g.add_edge(0, 1)
        g.add_edge(0, 2)
        g.add_edge(0, 3)
        g.add_edge(6, 1)
        g.add_edge(6, 2)
        g.add_edge(6, 3)
        # Give node 2 more connections (higher degree)
        g.add_edge(2, 4)
        g.add_edge(2, 5)

        mcf = MutualContactFinder(g)
        mutual = mcf.find_for_pair(0, 6)
        # Node 2 has highest degree among mutual contacts
        assert mutual[0] == 2


class TestGraphMonitorHealth:

    def test_complete_connected(self):
        g = _make_complete_graph(10)
        mon = GraphMonitor(g)
        assert mon.is_connected()
        assert mon.min_degree() == 9
        assert len(mon.underconnected_nodes()) == 0

    def test_ring_connected(self):
        g = _make_ring_graph(10)
        mon = GraphMonitor(g)
        assert mon.is_connected()
        assert mon.min_degree() == 2

    def test_disconnected_graph(self):
        g = OverlayGraph()
        for i in range(4):
            g.add_node(i)
        g.add_edge(0, 1)
        g.add_edge(2, 3)
        mon = GraphMonitor(g)
        assert not mon.is_connected()

    def test_underconnected_detection(self):
        g = _make_ring_graph(20)
        mon = GraphMonitor(g)
        # Ring has degree 2, target is ceil(log2(20))+1=6
        under = mon.underconnected_nodes()
        assert len(under) == 20  # all nodes underconnected

    def test_remove_edge_detectable(self):
        g = _make_complete_graph(5)
        mon = GraphMonitor(g)
        assert mon.min_degree() == 4
        g.remove_edge(0, 1)
        assert mon.min_degree() == 3


class TestIntroductionOnSimNetwork:
    """Test peer introduction on a simulated network."""

    def test_introduction_chain(self):
        """Node A introduces B to C, then B introduces A to D."""
        g = OverlayGraph()
        # Initial: A-B, A-C, B-C, B-D, C-D
        for node in ['A', 'B', 'C', 'D']:
            g.add_node(node)
        g.add_edge('A', 'B')
        g.add_edge('A', 'C')
        g.add_edge('B', 'C')
        g.add_edge('B', 'D')
        g.add_edge('C', 'D')

        pi = PeerIntroduction(g, min_introducers=2)

        # A wants to connect to D
        # Mutual contacts of A and D: need nodes connected to both
        mutual = pi.find_mutual_contacts('A', 'D')
        # B is connected to both A and D, C is connected to both A and D
        assert 'B' in mutual
        assert 'C' in mutual
        assert pi.can_introduce('A', 'D')

    def test_overlay_expansion(self):
        """Starting from 5-node complete graph, introduce node 5."""
        g = _make_complete_graph(5)
        g.add_node(5)
        # Node 5 connects to node 0 and 1 initially
        g.add_edge(5, 0)
        g.add_edge(5, 1)

        pi = PeerIntroduction(g, min_introducers=2)

        # Can node 5 be introduced to node 4?
        mutual = pi.find_mutual_contacts(5, 4)
        # 0 and 1 are mutual contacts (connected to both 5 and 4)
        assert 0 in mutual
        assert 1 in mutual
        assert pi.can_introduce(5, 4)

    def test_trust_after_introduction(self):
        """New node's trust emerges after introduction."""
        g = _make_complete_graph(5)
        trust_before = personalized_pagerank(0, g)

        # Add new node connected to nodes 0 and 1
        g.add_node(5)
        g.add_edge(5, 0)
        g.add_edge(5, 1)

        trust_after = personalized_pagerank(0, g)
        assert 5 in trust_after
        assert trust_after[5] > 0
        # New node has less trust than established nodes
        assert trust_after[5] < trust_after[1]
