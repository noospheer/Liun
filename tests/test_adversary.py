"""Tests for adversary attack simulations."""

import random
import pytest
from liun.gf61 import M61, rand_element
from liun.overlay import OverlayGraph, personalized_pagerank
from liun.dkg import DKG
from liun.uss import SigningPolynomial, Verifier
from liun.shamir import split
from sim.adversary.eclipse import EclipseAttack, EclipseTopologyAttack
from sim.adversary.sybil import SybilAttack
from sim.adversary.collusion import CollusionAttack
from sim.adversary.slow_compromise import SlowCompromise


class TestEclipseAttack:

    def test_partial_eclipse_fails(self):
        """Eve observing 75% of paths cannot reconstruct."""
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, 20, 14, rng)

        attack = EclipseAttack(n_paths=20, eclipse_fraction=0.75)
        result = attack.run(shares)

        assert not result['can_reconstruct']
        assert len(result['unobserved']) == 5

    def test_full_eclipse_succeeds(self):
        """Eve observing 100% of paths gets all shares."""
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, 20, 14, rng)

        attack = EclipseAttack(n_paths=20, eclipse_fraction=1.0)
        result = attack.run(shares)

        assert result['can_reconstruct']
        assert result['coverage'] == 1.0

    def test_50_percent_eclipse(self):
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, 20, 14, rng)

        attack = EclipseAttack(n_paths=20, eclipse_fraction=0.5)
        result = attack.run(shares)
        assert not result['can_reconstruct']
        assert result['coverage'] == 0.5

    def test_bootstrap_succeeds_with_one_clean_path(self):
        """Bootstrap succeeds when at least 1 path is unobserved."""
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, 20, 14, rng)

        attack = EclipseAttack(n_paths=20, eclipse_fraction=0.95)
        result = attack.run(shares)
        assert not result['can_reconstruct']
        assert len(result['unobserved']) == 1

    def test_topology_eclipse(self):
        """All paths through Eve's nodes in a controlled topology."""
        g = OverlayGraph()
        # Star topology: all paths from 0 to 4 go through node 2
        for i in range(5):
            g.add_node(i)
        g.add_edge(0, 1)
        g.add_edge(1, 2)
        g.add_edge(2, 3)
        g.add_edge(3, 4)

        eve_nodes = {2}
        attack = EclipseTopologyAttack(g, eve_nodes, target=4)
        assert attack.all_paths_through_eve(0)

    def test_topology_not_eclipsed(self):
        """Multiple independent paths prevent eclipse."""
        g = OverlayGraph()
        for i in range(5):
            g.add_node(i)
        g.add_edge(0, 1)
        g.add_edge(1, 4)
        g.add_edge(0, 2)
        g.add_edge(2, 4)  # alternative path not through 1

        eve_nodes = {1}
        attack = EclipseTopologyAttack(g, eve_nodes, target=4)
        assert not attack.all_paths_through_eve(0)


class TestSybilAttack:

    def _make_honest_graph(self, n):
        g = OverlayGraph()
        for i in range(n):
            g.add_node(i)
            for j in range(i + 1, n):
                g.add_edge(i, j)
        return g

    def test_sybil_trust_bounded_by_attack_edges(self):
        """1000 Sybils with 3 attack edges ~ trust of 3 honest nodes."""
        g = self._make_honest_graph(20)
        attack = SybilAttack(g, n_sybil=100, attack_edges=3)
        attack.inject()
        result = attack.measure_trust_capture(seed=0)

        # Sybil trust equivalent should be roughly proportional to g
        assert result['sybil_equivalent_honest'] < 10  # generous bound

    def test_more_attack_edges_more_trust(self):
        """Trust capture scales with attack edges."""
        g = self._make_honest_graph(20)
        results = {}
        for g_edges in [1, 3, 5]:
            attack = SybilAttack(g, n_sybil=50, attack_edges=g_edges,
                                 rng=random.Random(42))
            attack.inject()
            results[g_edges] = attack.measure_trust_capture(seed=0)

        assert results[3]['sybil_trust'] > results[1]['sybil_trust']
        assert results[5]['sybil_trust'] > results[3]['sybil_trust']

    def test_sybil_count_doesnt_matter(self):
        """Doubling sybils with same g doesn't double trust."""
        g = self._make_honest_graph(20)

        attack_50 = SybilAttack(g, n_sybil=50, attack_edges=3,
                                rng=random.Random(42))
        attack_50.inject()
        r50 = attack_50.measure_trust_capture(seed=0)

        attack_200 = SybilAttack(g, n_sybil=200, attack_edges=3,
                                 rng=random.Random(42))
        attack_200.inject()
        r200 = attack_200.measure_trust_capture(seed=0)

        # Trust should be similar despite 4x more sybils
        ratio = r200['sybil_trust'] / r50['sybil_trust']
        assert ratio < 2.0  # much less than 4x


class TestCollusionAttack:

    def test_below_threshold_cannot_reconstruct(self):
        """t < k corrupt nodes cannot reconstruct F(0)."""
        rng = random.Random(42)
        node_ids = list(range(1, 21))
        dkg = DKG(node_ids, threshold=14, rng=rng)
        dkg.run()

        # Adversary controls 6 nodes (< 14 threshold)
        corrupt_ids = list(range(1, 7))
        attack = CollusionAttack(dkg, corrupt_ids)
        result = attack.attempt_reconstruction()

        assert not result['success']
        assert result['n_points'] == 6
        assert result['threshold'] == 14

    def test_at_threshold_can_reconstruct(self):
        """t = k corrupt nodes CAN reconstruct."""
        rng = random.Random(42)
        node_ids = list(range(1, 21))
        dkg = DKG(node_ids, threshold=14, rng=rng)
        dkg.run()

        corrupt_ids = list(range(1, 15))  # 14 = threshold
        attack = CollusionAttack(dkg, corrupt_ids)
        result = attack.attempt_reconstruction()

        assert result['success']

    def test_forgery_fails_below_threshold(self):
        """Colluding nodes below threshold cannot forge signatures."""
        rng = random.Random(42)
        node_ids = list(range(1, 21))
        degree = 13  # threshold - 1
        dkg = DKG(node_ids, threshold=14, rng=rng)
        dkg.run()

        # Create verification points from the combined polynomial
        secret = dkg.get_combined_secret()
        # Build points for a verifier
        vp_xs = list(range(100, 100 + degree + 1))
        from liun.gf61 import lagrange_interpolate
        combined_points = [(nid, dkg.combined_shares[nid])
                          for nid in node_ids[:14]]
        vps = [(x, lagrange_interpolate(combined_points, x)) for x in vp_xs]

        corrupt_ids = [1, 3, 6]  # 3 < 14
        attack = CollusionAttack(dkg, corrupt_ids)
        msg = rand_element(rng)
        result = attack.attempt_forgery(msg, vps, degree)

        assert not result['success']
        assert result['method'] == 'random_guess'


class TestSlowCompromise:

    def _make_complete_graph(self, n):
        g = OverlayGraph()
        for i in range(n):
            g.add_node(i)
            for j in range(i + 1, n):
                g.add_edge(i, j)
        return g

    def test_initial_no_compromise(self):
        g = self._make_complete_graph(20)
        sc = SlowCompromise(g, set(range(20)))
        result = sc.measure_trust(seed=0)
        assert result['n_compromised'] == 0
        assert result['compromised_trust'] == 0.0

    def test_compromise_increases_over_epochs(self):
        g = self._make_complete_graph(20)
        sc = SlowCompromise(g, set(range(20)), rng=random.Random(42))
        results = sc.run_epochs(10, seed=0)

        # Compromised trust should increase
        assert results[-1]['compromised_trust'] > results[0]['compromised_trust']
        assert results[-1]['n_compromised'] == 10

    def test_consensus_disruption_threshold(self):
        """Eventually compromised trust exceeds 1/3."""
        g = self._make_complete_graph(20)
        sc = SlowCompromise(g, set(range(20)), rng=random.Random(42))
        results = sc.run_epochs(15, seed=0)

        # In a complete graph, compromising >1/3 nodes = >1/3 trust
        # Should happen around epoch 7 (7/20 = 35% > 33%)
        epochs_to_disruption = sc.epochs_to_disruption()
        assert epochs_to_disruption > 0
        assert epochs_to_disruption <= 15

    def test_trust_trajectory_monotonic(self):
        """Compromised fraction increases monotonically."""
        g = self._make_complete_graph(20)
        sc = SlowCompromise(g, set(range(20)), rng=random.Random(42))
        results = sc.run_epochs(10, seed=0)

        for i in range(1, len(results)):
            assert results[i]['compromised_fraction'] >= results[i-1]['compromised_fraction']
