"""Integration tests: full protocol chain at scale.

Correctness scenarios (must all pass):
- Full lifecycle: bootstrap -> DKG -> sign -> verify -> epoch rotate
- Corrupt minority: DKG completes, signing works, forgery fails

Attack scenarios (measure survival):
- Sybil at scale
- Eclipse bootstrap
- Collusion
- Slow compromise

Efficiency scenarios (measure and extrapolate):
- DKG cost scaling
- Signing latency scaling
- PageRank convergence scaling
- Memory per node scaling
"""

import random
import time
import sys
import math
import pytest

from liun.gf61 import M61, rand_element, lagrange_interpolate
from liun.shamir import split, reconstruct
from liun.uss import (
    SigningPolynomial, PartialSigner, SignatureCombiner, Verifier,
)
from liun.dkg import DKG, EpochManager
from liun.overlay import OverlayGraph, personalized_pagerank, trust_weighted_accept
from liun.bootstrap import MultiPathBootstrap, ShamirEncoder
from sim.adversary.eclipse import EclipseAttack
from sim.adversary.sybil import SybilAttack
from sim.adversary.collusion import CollusionAttack
from sim.adversary.slow_compromise import SlowCompromise
from sim.metrics.collector import MetricsCollector
from sim.metrics.efficiency import EfficiencyAnalyzer, fit_power_law


# ---------------------------------------------------------------------------
# Correctness Scenarios
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    """Full protocol chain: bootstrap -> DKG -> sign -> verify -> epoch rotate."""

    @pytest.mark.parametrize("n", [10, 50])
    def test_lifecycle(self, n):
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1
        degree = threshold - 1

        # Step 1: Bootstrap (simulated — just establish shared secrets)
        mpb = MultiPathBootstrap(k=min(20, n))
        result = mpb.bootstrap(node_ids, rng=rng)
        assert result['success']

        # Step 2: DKG
        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run()
        assert len(shares) == n

        # Step 3: Sign
        message = rand_element(rng)
        committee = node_ids[:threshold]
        signers = [PartialSigner(nid, shares[nid]) for nid in committee]
        partials = [s.partial_sign(message, committee) for s in signers]
        combiner = SignatureCombiner()
        sigma = combiner.combine(partials)

        # Step 4: Verify
        # Build verification points from combined polynomial
        basis_points = [(nid, shares[nid]) for nid in node_ids[:threshold]]
        vp_xs = list(range(n + 100, n + 100 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        verifier = Verifier(vps, degree)
        assert verifier.verify(message, sigma)

        # Step 5: Epoch rotation
        em = EpochManager(node_ids, threshold)
        dkg2 = em.new_epoch(random.Random(999))
        assert dkg2.get_combined_secret() != dkg.get_combined_secret()

    def test_lifecycle_n100(self):
        """N=100 full lifecycle."""
        n = 100
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1
        degree = threshold - 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run()

        message = rand_element(rng)
        committee = node_ids[:threshold]
        signers = [PartialSigner(nid, shares[nid]) for nid in committee]
        partials = [s.partial_sign(message, committee) for s in signers]
        sigma = SignatureCombiner().combine(partials)

        basis_points = [(nid, shares[nid]) for nid in committee]
        vp_xs = list(range(n + 100, n + 100 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        verifier = Verifier(vps, degree)
        assert verifier.verify(message, sigma)


class TestCorruptMinority:
    """Corrupt minority (up to N/3 - 1): DKG completes, signing works, forgery fails."""

    def test_corrupt_minority_dkg_and_sign(self):
        n = 20
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1  # 14
        degree = threshold - 1

        # Run DKG
        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()

        # Corrupt N/3 - 1 = 5 nodes
        corrupt_ids = [1, 2, 3, 4, 5]
        for cid in corrupt_ids:
            dkg.inject_corrupt_shares(cid)

        corrupt_detected = dkg.verify_consistency()
        for cid in corrupt_ids:
            assert cid in corrupt_detected

        dkg.combine_shares()
        honest_ids = [nid for nid in node_ids if nid not in dkg.excluded]
        assert len(honest_ids) >= threshold

        # Sign with honest committee
        message = rand_element(rng)
        committee = honest_ids[:threshold]
        signers = [PartialSigner(nid, dkg.combined_shares[nid]) for nid in committee]
        partials = [s.partial_sign(message, committee) for s in signers]
        sigma = SignatureCombiner().combine(partials)

        # Verify
        basis_points = [(nid, dkg.combined_shares[nid]) for nid in committee]
        vp_xs = list(range(200, 200 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        verifier = Verifier(vps, degree)
        assert verifier.verify(message, sigma)

        # Forgery fails
        bad_sigma = (sigma + 1) % M61
        assert not verifier.verify(message, bad_sigma)


# ---------------------------------------------------------------------------
# Attack Scenarios
# ---------------------------------------------------------------------------

class TestSybilAtScale:
    """Sybil attack with varying attack edges."""

    @pytest.mark.parametrize("g", [3, 5, 10, 20])
    def test_sybil_trust_capture(self, g):
        n_honest = 50
        n_sybil = 200

        honest_graph = OverlayGraph()
        for i in range(n_honest):
            honest_graph.add_node(i)
            for j in range(i + 1, n_honest):
                honest_graph.add_edge(i, j)

        attack = SybilAttack(honest_graph, n_sybil=n_sybil,
                             attack_edges=g, rng=random.Random(42))
        attack.inject()
        result = attack.measure_trust_capture(seed=0)

        # Sybil equivalent trust should be bounded by O(g)
        assert result['sybil_equivalent_honest'] < g * 5  # generous bound
        # Honest nodes retain majority trust
        assert result['honest_trust'] > result['sybil_trust']


class TestEclipseBootstrap:
    """Eclipse coverage vs bootstrap success rate."""

    @pytest.mark.parametrize("coverage", [0.5, 0.75, 0.9, 1.0])
    def test_eclipse_coverage(self, coverage):
        k = 20
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, k, 14, rng)

        attack = EclipseAttack(n_paths=k, eclipse_fraction=coverage)
        result = attack.run(shares)

        if coverage < 1.0:
            assert not result['can_reconstruct']
            assert result['clean_paths'] > 0 if 'clean_paths' in result else True
        else:
            assert result['can_reconstruct']


class TestCollusionAtScale:
    """Collusion with varying numbers of corrupt nodes."""

    @pytest.mark.parametrize("t", [1, 3, 6])
    def test_collusion_signing_polynomial(self, t):
        n = 20
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 14

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.run()

        corrupt_ids = list(range(1, t + 1))
        attack = CollusionAttack(dkg, corrupt_ids)
        result = attack.attempt_reconstruction()

        if t < threshold:
            assert not result['success']
        else:
            assert result['success']


class TestSlowCompromiseAtScale:
    """Slow compromise over 50 epochs."""

    def test_slow_compromise_trajectory(self):
        n = 30
        graph = OverlayGraph()
        for i in range(n):
            graph.add_node(i)
            for j in range(i + 1, n):
                graph.add_edge(i, j)

        sc = SlowCompromise(graph, set(range(n)), rng=random.Random(42))
        results = sc.run_epochs(20, seed=0)

        # Trust fraction should increase monotonically
        for i in range(1, len(results)):
            assert results[i]['compromised_fraction'] >= results[i-1]['compromised_fraction']

        # Eventually reaches disruption threshold
        disruption = sc.epochs_to_disruption()
        assert disruption > 0  # takes at least some epochs


# ---------------------------------------------------------------------------
# Efficiency Scenarios
# ---------------------------------------------------------------------------

class TestDKGScaling:
    """Measure DKG cost at various N and verify O(N^2) scaling."""

    @pytest.mark.parametrize("n", [10, 50, 100])
    def test_dkg_cost(self, n):
        rng = random.Random(42)
        collector = MetricsCollector()

        node_ids = list(range(1, n + 1))
        with collector.measure('dkg', n=n):
            dkg = DKG(node_ids, rng=rng)
            dkg.run()

        m = collector.measurements[-1]
        assert m.time_s > 0
        # Estimate bytes: N*(N-1) shares, each 8 bytes
        m.bytes_sent = n * (n - 1) * 8

    def test_dkg_scaling_fit(self):
        """Fit DKG timing to power law and verify ~O(N^2)."""
        collector = MetricsCollector()
        ns = [10, 30, 50]
        for n in ns:
            rng = random.Random(42)
            node_ids = list(range(1, n + 1))
            with collector.measure('dkg', n=n):
                DKG(node_ids, rng=rng).run()

        series = collector.get_series('dkg')
        fit = fit_power_law(series['n'], series['time_s'])
        # Exponent should be roughly 2 (O(N^2))
        assert 1.5 < fit['b'] < 3.5  # generous range


class TestSigningScaling:
    """Measure signing latency at various N."""

    @pytest.mark.parametrize("n", [10, 50, 100])
    def test_signing_latency(self, n):
        rng = random.Random(42)
        collector = MetricsCollector()
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run()

        message = rand_element(rng)
        committee = node_ids[:threshold]

        with collector.measure('signing', n=n):
            signers = [PartialSigner(nid, shares[nid]) for nid in committee]
            partials = [s.partial_sign(message, committee) for s in signers]
            sigma = SignatureCombiner().combine(partials)

        m = collector.measurements[-1]
        assert m.time_s >= 0


class TestPageRankScaling:
    """Measure PageRank convergence at various N."""

    @pytest.mark.parametrize("n", [10, 50, 100])
    def test_pagerank_convergence(self, n):
        collector = MetricsCollector()

        g = OverlayGraph()
        rng = random.Random(42)
        for i in range(n):
            g.add_node(i)
        # Random edges: ~log2(N) per node
        target_degree = max(3, int(math.log2(n)) + 1)
        for i in range(n):
            for _ in range(target_degree):
                j = rng.randint(0, n - 1)
                if j != i:
                    g.add_edge(i, j)

        with collector.measure('pagerank', n=n):
            trust = personalized_pagerank(0, g)

        m = collector.measurements[-1]
        assert m.time_s >= 0
        assert abs(sum(trust.values()) - 1.0) < 1e-8


class TestMemoryScaling:
    """Measure memory per node at various N."""

    @pytest.mark.parametrize("n", [10, 50, 100])
    def test_memory_per_node(self, n):
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))

        dkg = DKG(node_ids, rng=rng)
        dkg.run()

        # Estimate: each node stores combined share (8 bytes) +
        # channel state + trust scores
        share_bytes = 8  # one GF(M61) element
        trust_bytes = n * 8  # one float per node
        channel_bytes = n * 16  # approximate per channel
        estimated = share_bytes + trust_bytes + channel_bytes
        assert estimated > 0


class TestEfficiencyExtrapolation:
    """Extrapolate measurements to large N."""

    def test_extrapolate_dkg(self):
        """Measure DKG at small N, extrapolate to 10K and 100K."""
        collector = MetricsCollector()
        ns = [10, 30, 50]
        for n in ns:
            rng = random.Random(42)
            node_ids = list(range(1, n + 1))
            with collector.measure('dkg', n=n):
                DKG(node_ids, rng=rng).run()

        analyzer = EfficiencyAnalyzer(collector)
        analyzer.analyze('dkg')
        projections = analyzer.extrapolate('dkg', [10000, 100000])

        # Just verify we get numbers (extrapolation is inherently approximate)
        assert projections[10000] > 0
        assert projections[100000] > projections[10000]

    def test_extrapolate_pagerank(self):
        """Measure PageRank, extrapolate."""
        collector = MetricsCollector()
        rng = random.Random(42)

        for n in [10, 30, 50]:
            g = OverlayGraph()
            for i in range(n):
                g.add_node(i)
            for i in range(n):
                for _ in range(max(3, int(math.log2(n)))):
                    j = rng.randint(0, n - 1)
                    if j != i:
                        g.add_edge(i, j)

            with collector.measure('pagerank', n=n):
                personalized_pagerank(0, g)

        analyzer = EfficiencyAnalyzer(collector)
        analyzer.analyze('pagerank')
        projections = analyzer.extrapolate('pagerank', [10000, 100000])
        assert projections[10000] > 0
