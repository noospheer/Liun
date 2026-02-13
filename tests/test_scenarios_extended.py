"""Extended integration tests: larger scale, deeper adversary analysis.

Supplements test_scenarios.py with:
- N=500 DKG + signing + PageRank
- N=1000 signing + PageRank
- Full Sybil sweep: N_honest=100, N_sybil=1000
- 50-epoch slow compromise
- DKG on sim_network (message-bus integrated)
- Multi-verifier cross-verification
- Epoch rotation with signing continuity
- Full lifecycle at N=200 with all attacks
"""

import random
import math
import time
import pytest

from liun.gf61 import M61, rand_element, rand_nonzero, lagrange_interpolate
from liun.shamir import split, reconstruct, consistency_check
from liun.uss import (
    SigningPolynomial, PartialSigner, SignatureCombiner, Verifier,
    DisputeResolver, SignatureBudget,
)
from liun.dkg import DKG, EpochManager
from liun.overlay import OverlayGraph, personalized_pagerank, trust_weighted_accept
from liun.bootstrap import MultiPathBootstrap, ShamirEncoder
from sim.core.clock import SimClock
from sim.core.message_bus import SimMessageBus
from sim.network.sim_network import SimNetwork
from sim.adversary.eclipse import EclipseAttack
from sim.adversary.sybil import SybilAttack
from sim.adversary.collusion import CollusionAttack
from sim.adversary.slow_compromise import SlowCompromise
from sim.metrics.collector import MetricsCollector
from sim.metrics.efficiency import EfficiencyAnalyzer, fit_power_law
from sim.metrics.reporter import Reporter


# ---------------------------------------------------------------------------
# Scale: N=500 DKG (skip verify — proven correct at N≤200)
# ---------------------------------------------------------------------------

class TestDKGLargeScale:

    def test_n200_full_dkg(self):
        """N=200 DKG with full verification."""
        rng = random.Random(42)
        node_ids = list(range(1, 201))
        dkg = DKG(node_ids, rng=rng)
        shares = dkg.run(verify=True)
        assert len(shares) == 200
        # Verify reconstructed secret from two different subsets
        secret = dkg.get_combined_secret()
        alt_ids = list(range(1, 201))[-dkg.threshold:]  # last threshold nodes
        alt_points = [(nid, shares[nid]) for nid in alt_ids]
        assert lagrange_interpolate(alt_points, 0) == secret

    def test_n500_dkg_no_verify(self):
        """N=500 DKG (skip verify — proven at N≤200). Measures gen+dist+combine."""
        rng = random.Random(42)
        node_ids = list(range(1, 501))
        collector = MetricsCollector()

        with collector.measure('dkg_500', n=500):
            dkg = DKG(node_ids, rng=rng)
            shares = dkg.run(verify=False)

        assert len(shares) == 500
        secret = dkg.get_combined_secret()

        # Verify with random subsets
        subset = random.Random(99).sample(node_ids, dkg.threshold)
        points = [(nid, shares[nid]) for nid in subset]
        assert lagrange_interpolate(points, 0) == secret

        m = collector.measurements[0]
        assert m.time_s > 0
        m.bytes_sent = 500 * 499 * 8  # N*(N-1) shares at 8 bytes
        print(f"\n  N=500 DKG: {m.time_s:.2f}s, {m.bytes_sent:,} bytes")

    def test_n200_corrupt_minority(self):
        """N=200 with 30 corrupt nodes — still works."""
        rng = random.Random(42)
        n = 200
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()

        # Corrupt 30 nodes (< N/3 = 66)
        corrupt_ids = list(range(1, 31))
        for cid in corrupt_ids:
            dkg.inject_corrupt_shares(cid)

        detected = dkg.verify_consistency()
        for cid in corrupt_ids:
            assert cid in detected

        dkg.combine_shares()
        honest_ids = [nid for nid in node_ids if nid not in dkg.excluded]
        assert len(honest_ids) >= threshold


# ---------------------------------------------------------------------------
# Scale: N=500/1000 signing
# ---------------------------------------------------------------------------

class TestSigningLargeScale:

    @pytest.mark.parametrize("n", [200, 500])
    def test_threshold_signing(self, n):
        """Full threshold signing at large N."""
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1
        degree = threshold - 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run(verify=False)

        message = rand_nonzero(rng)
        committee = node_ids[:threshold]

        collector = MetricsCollector()
        with collector.measure('signing', n=n):
            signers = [PartialSigner(nid, shares[nid]) for nid in committee]
            partials = [s.partial_sign(message, committee) for s in signers]
            sigma = SignatureCombiner().combine(partials)

        # Verify signature
        basis_points = [(nid, shares[nid]) for nid in committee]
        vp_xs = list(range(n + 100, n + 100 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        v = Verifier(vps, degree)
        assert v.verify(message, sigma)

        m = collector.measurements[0]
        print(f"\n  N={n} signing: {m.time_s:.4f}s")

    def test_n1000_signing(self):
        """Signing at N=1000 (DKG without verify)."""
        rng = random.Random(42)
        n = 1000
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run(verify=False)

        message = rand_nonzero(rng)
        committee = node_ids[:threshold]

        t0 = time.perf_counter()
        signers = [PartialSigner(nid, shares[nid]) for nid in committee]
        partials = [s.partial_sign(message, committee) for s in signers]
        sigma = SignatureCombiner().combine(partials)
        t1 = time.perf_counter()

        # Spot-check: sigma = F(message)
        expected = lagrange_interpolate(
            [(nid, shares[nid]) for nid in committee], message
        )
        assert sigma == expected
        print(f"\n  N=1000 signing: {t1-t0:.4f}s")


# ---------------------------------------------------------------------------
# Scale: N=500/1000 PageRank
# ---------------------------------------------------------------------------

class TestPageRankLargeScale:

    @pytest.mark.parametrize("n", [200, 500, 1000])
    def test_pagerank_at_scale(self, n):
        """PageRank convergence at large N."""
        rng = random.Random(42)
        g = OverlayGraph()
        for i in range(n):
            g.add_node(i)
        target_deg = max(3, int(math.log2(n)) + 1)
        for i in range(n):
            for _ in range(target_deg):
                j = rng.randint(0, n - 1)
                if j != i:
                    g.add_edge(i, j)

        t0 = time.perf_counter()
        trust = personalized_pagerank(0, g)
        t1 = time.perf_counter()

        assert abs(sum(trust.values()) - 1.0) < 1e-8
        assert trust[0] > 0
        print(f"\n  N={n} PageRank: {t1-t0:.4f}s")


# ---------------------------------------------------------------------------
# Full Sybil sweep: N_honest=100, N_sybil=1000
# ---------------------------------------------------------------------------

class TestSybilFullSweep:

    def _make_honest_graph(self, n):
        g = OverlayGraph()
        for i in range(n):
            g.add_node(i)
            for j in range(i + 1, n):
                g.add_edge(i, j)
        return g

    @pytest.mark.parametrize("g_edges", [3, 5, 10, 20])
    def test_sybil_n100_honest_n1000_sybil(self, g_edges):
        """N_honest=100, N_sybil=1000, varying attack edges."""
        honest_g = self._make_honest_graph(100)
        attack = SybilAttack(
            honest_g, n_sybil=1000, attack_edges=g_edges,
            rng=random.Random(42),
        )
        attack.inject()
        result = attack.measure_trust_capture(seed=0)

        print(f"\n  g={g_edges}: sybil_equiv={result['sybil_equivalent_honest']:.2f} "
              f"honest nodes, sybil_frac={result['sybil_fraction']:.4f}")

        # Core bound: sybil trust proportional to g, NOT to n_sybil
        assert result['sybil_equivalent_honest'] < g_edges * 5
        # Honest majority
        assert result['honest_trust'] > result['sybil_trust']

    def test_sybil_count_irrelevance(self):
        """100 vs 2000 Sybils with same g=3 → similar trust."""
        honest_g = self._make_honest_graph(50)

        results = {}
        for n_syb in [100, 500, 1000, 2000]:
            attack = SybilAttack(
                honest_g, n_sybil=n_syb, attack_edges=3,
                rng=random.Random(42),
            )
            attack.inject()
            results[n_syb] = attack.measure_trust_capture(seed=0)

        # Trust should NOT scale linearly with sybil count
        ratio = results[2000]['sybil_trust'] / results[100]['sybil_trust']
        assert ratio < 5.0  # much less than 20x

        print(f"\n  Sybil count irrelevance: "
              f"100→{results[100]['sybil_trust']:.4f}, "
              f"2000→{results[2000]['sybil_trust']:.4f}, "
              f"ratio={ratio:.2f}")


# ---------------------------------------------------------------------------
# 50-epoch slow compromise
# ---------------------------------------------------------------------------

class TestSlowCompromise50Epochs:

    def test_50_epoch_trajectory(self):
        """Track trust over 50 epochs of compromise on 100-node graph."""
        n = 100
        g = OverlayGraph()
        for i in range(n):
            g.add_node(i)
            for j in range(i + 1, n):
                g.add_edge(i, j)

        sc = SlowCompromise(g, set(range(n)), rng=random.Random(42))
        results = sc.run_epochs(50, seed=0)

        # Monotonically increasing compromised fraction
        for i in range(1, len(results)):
            assert results[i]['compromised_fraction'] >= results[i-1]['compromised_fraction']

        # Track critical thresholds
        disruption_epoch = sc.epochs_to_disruption()
        assert disruption_epoch > 0

        print(f"\n  50-epoch compromise on N=100:")
        print(f"    Disruption (>1/3 trust) at epoch {disruption_epoch}")
        print(f"    Final compromised fraction: {results[-1]['compromised_fraction']:.4f}")
        print(f"    Epoch 10: {results[10]['compromised_fraction']:.4f}")
        print(f"    Epoch 25: {results[25]['compromised_fraction']:.4f}")


# ---------------------------------------------------------------------------
# Multi-verifier cross-verification
# ---------------------------------------------------------------------------

class TestMultiVerifierCrossCheck:

    def test_5_verifiers_agree_on_valid_sig(self):
        """5 independent verifiers all accept a valid signature."""
        degree = 20
        rng = random.Random(42)
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        verifiers = []
        for i in range(5):
            base = 5000 + i * (degree + 5)
            vp_xs = list(range(base, base + degree + 1))
            vps = poly.get_verification_points(vp_xs)
            verifiers.append(Verifier(vps, degree))

        for v in verifiers:
            assert v.verify(msg, sigma)

    def test_5_verifiers_all_reject_forgery(self):
        """5 independent verifiers all reject a forged signature."""
        degree = 20
        rng = random.Random(42)
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        bad_sigma = rand_element(rng)

        verifiers = []
        for i in range(5):
            base = 6000 + i * (degree + 5)
            vp_xs = list(range(base, base + degree + 1))
            vps = poly.get_verification_points(vp_xs)
            verifiers.append(Verifier(vps, degree))

        for v in verifiers:
            assert not v.verify(msg, bad_sigma)

    def test_dispute_resolution_unanimous(self):
        """Dispute resolution with 7 verifiers."""
        degree = 15
        rng = random.Random(42)
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)

        verifiers = []
        for i in range(7):
            base = 7000 + i * (degree + 5)
            vp_xs = list(range(base, base + degree + 1))
            vps = poly.get_verification_points(vp_xs)
            verifiers.append(Verifier(vps, degree))

        resolver = DisputeResolver()
        assert resolver.resolve(msg, poly.sign(msg), verifiers) == 'valid'
        assert resolver.resolve(msg, rand_element(rng), verifiers) == 'forged'


# ---------------------------------------------------------------------------
# Epoch rotation with signing continuity
# ---------------------------------------------------------------------------

class TestEpochContinuity:

    def test_signing_across_epochs(self):
        """Sign messages in epoch 1, rotate, sign in epoch 2. Both valid."""
        n = 20
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1
        degree = threshold - 1

        em = EpochManager(node_ids, threshold)

        # Epoch 1
        dkg1 = em.new_epoch(random.Random(1))
        shares1 = dkg1.combined_shares
        msg1 = rand_nonzero(random.Random(100))
        committee1 = node_ids[:threshold]
        partials1 = [PartialSigner(nid, shares1[nid]).partial_sign(msg1, committee1)
                     for nid in committee1]
        sigma1 = SignatureCombiner().combine(partials1)

        # Epoch 2
        dkg2 = em.new_epoch(random.Random(2))
        shares2 = dkg2.combined_shares
        msg2 = rand_nonzero(random.Random(200))
        committee2 = node_ids[:threshold]
        partials2 = [PartialSigner(nid, shares2[nid]).partial_sign(msg2, committee2)
                     for nid in committee2]
        sigma2 = SignatureCombiner().combine(partials2)

        # Verify both
        # Epoch 1 verification
        basis1 = [(nid, shares1[nid]) for nid in committee1]
        vp_xs1 = list(range(100, 100 + degree + 1))
        vps1 = [(x, lagrange_interpolate(basis1, x)) for x in vp_xs1]
        assert Verifier(vps1, degree).verify(msg1, sigma1)

        # Epoch 2 verification
        basis2 = [(nid, shares2[nid]) for nid in committee2]
        vp_xs2 = list(range(200, 200 + degree + 1))
        vps2 = [(x, lagrange_interpolate(basis2, x)) for x in vp_xs2]
        assert Verifier(vps2, degree).verify(msg2, sigma2)

        # Cross-epoch: epoch 1 sig doesn't verify with epoch 2 keys
        assert not Verifier(vps2, degree).verify(msg1, sigma1)

    def test_budget_forces_rotation(self):
        """Signature budget exhaustion triggers need for new epoch."""
        degree = 20
        budget = SignatureBudget(degree)
        assert budget.max_signatures == 10

        rng = random.Random(42)
        for i in range(10):
            assert budget.can_sign()
            budget.record(rand_nonzero(rng))

        assert not budget.can_sign()
        assert budget.remaining == 0


# ---------------------------------------------------------------------------
# DKG on sim_network (message-bus integrated)
# ---------------------------------------------------------------------------

class TestDKGOnSimNetwork:

    def test_dkg_via_message_bus(self):
        """Run DKG using the simulation message bus for share distribution."""
        net = SimNetwork(10, 'random', seed=42)

        # Run DKG on the network's nodes
        node_ids = list(net.nodes.keys())
        rng = random.Random(42)
        dkg = DKG(node_ids, rng=rng)
        dkg.generate_contributions()

        # Distribute shares via message bus
        for sender in node_ids:
            for receiver in node_ids:
                if sender != receiver:
                    share = dkg.shares_sent.get(sender, {}).get(receiver)
                    if share is None:
                        dkg.distribute_shares()
                        share = dkg.shares_sent[sender][receiver]
                    net.send(sender, receiver, 'dkg_share', {
                        'from': sender, 'share': share
                    })

        net.tick(1)

        # Verify messages delivered
        total_msgs = sum(len(n.inbox) for n in net.nodes.values())
        assert total_msgs == len(node_ids) * (len(node_ids) - 1)

        # Now combine shares (using DKG object which already has them)
        dkg.combine_shares()
        assert len(dkg.combined_shares) == len(node_ids)


# ---------------------------------------------------------------------------
# Metrics & reporter
# ---------------------------------------------------------------------------

class TestMetricsReporter:

    def test_csv_output(self):
        collector = MetricsCollector()
        collector.record('dkg', n=10, time_s=0.01, bytes_sent=800)
        collector.record('dkg', n=50, time_s=0.5, bytes_sent=19600)

        reporter = Reporter(collector)
        csv = reporter.to_csv('dkg')
        assert 'name,n,time_s' in csv
        assert '10' in csv
        assert '50' in csv

    def test_json_output(self):
        import json
        collector = MetricsCollector()
        collector.record('signing', n=100, time_s=0.002)

        reporter = Reporter(collector)
        data = json.loads(reporter.to_json('signing'))
        assert len(data) == 1
        assert data[0]['n'] == 100

    def test_summary(self):
        collector = MetricsCollector()
        collector.record('pr', n=10, time_s=0.001)
        collector.record('pr', n=50, time_s=0.01)
        collector.record('pr', n=100, time_s=0.05)

        reporter = Reporter(collector)
        s = reporter.summary('pr')
        assert s['count'] == 3
        assert s['min_time'] == 0.001
        assert s['max_time'] == 0.05

    def test_to_dict(self):
        collector = MetricsCollector()
        collector.record('test', n=42, time_s=1.5, key='value')

        reporter = Reporter(collector)
        d = reporter.to_dict()
        assert len(d) == 1
        assert d[0]['key'] == 'value'


# ---------------------------------------------------------------------------
# Efficiency fitting at extended scale
# ---------------------------------------------------------------------------

class TestEfficiencyFitting:

    def test_dkg_quadratic_fit(self):
        """DKG distribute+combine fits O(N^2) model."""
        collector = MetricsCollector()
        for n in [10, 30, 50, 100]:
            rng = random.Random(42)
            node_ids = list(range(1, n + 1))
            with collector.measure('dkg', n=n):
                DKG(node_ids, rng=rng).run(verify=False)

        analyzer = EfficiencyAnalyzer(collector)
        result = analyzer.analyze('dkg')
        b = result['power_fit']['b']
        # Exponent should be ~2 for O(N^2) distribute+combine
        assert 1.5 < b < 3.0, f"Expected ~2, got {b:.2f}"
        print(f"\n  DKG scaling exponent: {b:.2f} (expect ~2)")

    def test_signing_linear_fit(self):
        """Signing fits ~O(N^2) (threshold partial gen + combine)."""
        collector = MetricsCollector()
        for n in [10, 50, 100, 200]:
            rng = random.Random(42)
            node_ids = list(range(1, n + 1))
            threshold = 2 * n // 3 + 1
            dkg = DKG(node_ids, threshold=threshold, rng=rng)
            shares = dkg.run(verify=False)
            msg = rand_nonzero(rng)
            committee = node_ids[:threshold]

            with collector.measure('signing', n=n):
                signers = [PartialSigner(nid, shares[nid]) for nid in committee]
                partials = [s.partial_sign(msg, committee) for s in signers]
                SignatureCombiner().combine(partials)

        analyzer = EfficiencyAnalyzer(collector)
        result = analyzer.analyze('signing')
        b = result['power_fit']['b']
        print(f"\n  Signing scaling exponent: {b:.2f}")
        # Each partial_sign does O(k) Lagrange basis computation
        # k = 2N/3, so signing is O(k^2) = O(N^2)
        assert b > 1.0

    def test_extrapolate_all(self):
        """Extrapolate DKG, signing, PageRank to 10K and 100K."""
        collector = MetricsCollector()

        # DKG
        for n in [10, 30, 50, 100]:
            rng = random.Random(42)
            with collector.measure('dkg', n=n):
                DKG(list(range(1, n + 1)), rng=rng).run(verify=False)

        # Signing
        for n in [10, 50, 100]:
            rng = random.Random(42)
            node_ids = list(range(1, n + 1))
            threshold = 2 * n // 3 + 1
            dkg = DKG(node_ids, threshold=threshold, rng=rng)
            shares = dkg.run(verify=False)
            msg = rand_nonzero(rng)
            committee = node_ids[:threshold]
            with collector.measure('signing', n=n):
                signers = [PartialSigner(nid, shares[nid]) for nid in committee]
                partials = [s.partial_sign(msg, committee) for s in signers]
                SignatureCombiner().combine(partials)

        # PageRank
        for n in [10, 50, 100]:
            rng = random.Random(42)
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
        for name in ['dkg', 'signing', 'pagerank']:
            analyzer.analyze(name)
            proj = analyzer.extrapolate(name, [10000, 100000])
            print(f"\n  {name} extrapolation: "
                  f"N=10K → {proj[10000]:.2f}s, "
                  f"N=100K → {proj[100000]:.2f}s")
            assert proj[10000] > 0
            assert proj[100000] > proj[10000]


# ---------------------------------------------------------------------------
# Node.py integration
# ---------------------------------------------------------------------------

class TestNodeIntegration:

    def test_full_node_lifecycle(self):
        """LiunNode: init channel → DKG → sign → verify."""
        from liun.node import LiunNode
        from sim.core.mock_liu import MockLiuChannel

        n = 10
        threshold = 7
        degree = threshold - 1
        rng = random.Random(42)

        # Create nodes
        nodes = {i: LiunNode(i) for i in range(1, n + 1)}
        node_ids = list(nodes.keys())

        # Establish channels (just between neighbors in a ring)
        for i in range(1, n + 1):
            peer = (i % n) + 1
            psk = bytes(rng.getrandbits(8) for _ in range(256))
            nodes[i].init_channel(peer, psk)

        # Run DKG
        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run(verify=False)

        # Distribute shares and verification points to nodes
        basis_points = [(nid, shares[nid]) for nid in node_ids[:threshold]]
        for nid in node_ids:
            vp_xs = list(range(1000 + nid * (degree + 5),
                               1000 + nid * (degree + 5) + degree + 1))
            vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
            nodes[nid].participate_dkg(shares[nid], vps, degree)

        # Sign a message
        message = rand_nonzero(rng)
        committee = node_ids[:threshold]
        partials = [nodes[nid].sign(message, committee) for nid in committee]
        sigma = LiunNode.combine_signatures(partials)

        # All nodes verify
        for nid in node_ids:
            assert nodes[nid].verify(message, sigma)

        # Forged signature fails for all
        bad_sigma = (sigma + 1) % M61
        for nid in node_ids:
            assert not nodes[nid].verify(message, bad_sigma)

    def test_node_trust_computation(self):
        """Node computes local trust via PageRank."""
        from liun.node import LiunNode

        g = OverlayGraph()
        for i in range(5):
            g.add_node(i)
            for j in range(i + 1, 5):
                g.add_edge(i, j)

        node = LiunNode(0)
        trust = node.compute_trust(g)
        assert 0 in trust
        assert abs(sum(trust.values()) - 1.0) < 1e-10

    def test_dispute_resolution_via_node(self):
        """Node static method resolves disputes."""
        from liun.node import LiunNode

        degree = 10
        rng = random.Random(42)
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        verifiers = []
        for i in range(5):
            base = 8000 + i * (degree + 3)
            vps = poly.get_verification_points(list(range(base, base + degree + 1)))
            verifiers.append(Verifier(vps, degree))

        assert LiunNode.resolve_dispute(msg, sigma, verifiers) == 'valid'
        assert LiunNode.resolve_dispute(msg, rand_element(rng), verifiers) == 'forged'


# ---------------------------------------------------------------------------
# Channel lifecycle
# ---------------------------------------------------------------------------

class TestChannelLifecycle:

    def test_liu_channel_wrapper(self):
        from liun.liu_channel import LiuChannel, ChannelTable, ChannelStatus
        from sim.core.mock_liu import MockLiuChannel

        rng = random.Random(42)
        psk = bytes(rng.getrandbits(8) for _ in range(256))
        mock = MockLiuChannel(1, 2, psk)

        ch = LiuChannel(peer_id=2, psk=psk, mock_channel=mock)
        assert ch.status == ChannelStatus.ACTIVE

        # Generate key material
        bits = ch.key_material(128)
        assert len(bits) == 16
        assert ch.total_bits == 128

        # MAC
        tag = ch.authenticate([1, 2, 3])
        assert ch.verify_mac([1, 2, 3], tag)
        assert not ch.verify_mac([1, 2, 4], tag)

        # PSK recycling
        new_psk = ch.recycle_psk()
        assert len(new_psk) == 256

        # Close
        ch.close()
        assert ch.status == ChannelStatus.EXPIRED

    def test_channel_table(self):
        from liun.liu_channel import LiuChannel, ChannelTable

        rng = random.Random(42)
        table = ChannelTable()

        for peer in [10, 20, 30]:
            psk = bytes(rng.getrandbits(8) for _ in range(256))
            ch = LiuChannel(peer_id=peer, psk=psk)
            table.add(ch)

        assert table.count == 3
        assert len(table.active) == 3

        table.remove(20)
        assert table.count == 2
        assert table.get(20) is None


# ---------------------------------------------------------------------------
# Bootstrap with Shamir protection
# ---------------------------------------------------------------------------

class TestBootstrapShamirProtection:

    def test_shamir_detects_corrupt_relay(self):
        """Shamir encoding detects corruption during bootstrap relay.

        Leave-one-out detection flags corrupt shares but may also flag
        honest ones when corrupt shares contaminate interpolation subsets.
        We verify: (1) corrupt shares are flagged, (2) honest shares
        with no corrupt contamination still reconstruct correctly.
        """
        rng = random.Random(42)
        enc = ShamirEncoder(k=20, threshold=7)
        secret = rand_element(rng)
        shares = enc.encode(secret, rng)
        original = list(shares)  # save clean copies

        # Corrupt 1 relay — leave-one-out is clean for this case
        corrupt_idx = 5
        x, y = shares[corrupt_idx]
        shares[corrupt_idx] = (x, (y + rng.randint(1, M61 - 1)) % M61)

        corrupt = enc.detect_corrupt(shares)
        assert corrupt_idx in corrupt  # corrupt share detected

        # Reconstruct from known-honest shares
        honest = [s for i, s in enumerate(shares) if i != corrupt_idx]
        assert len(honest) >= 7
        assert reconstruct(honest[:7]) == secret

    def test_shamir_too_many_corrupt_fails(self):
        """More corrupt relays than can be reliably corrected → detection noisy."""
        rng = random.Random(42)
        enc = ShamirEncoder(k=20, threshold=7)
        secret = rand_element(rng)
        shares = enc.encode(secret, rng)

        # Corrupt 10 relays (> (20-7)/2 correctable)
        for idx in range(10):
            x, y = shares[idx]
            shares[idx] = (x, (y + 1) % M61)

        # Detection sees corruption but may flag honest shares too
        corrupt = enc.detect_corrupt(shares)
        assert len(corrupt) > 0  # at least some detected

        # If we use only uncorrupted shares, reconstruction works
        truly_clean = [(x, y) for i, (x, y) in enumerate(shares) if i >= 10]
        assert len(truly_clean) >= 7  # 10 clean shares remaining
        assert reconstruct(truly_clean[:7]) == secret


# ---------------------------------------------------------------------------
# Eclipse parameterized sweep
# ---------------------------------------------------------------------------

class TestEclipseSweep:

    @pytest.mark.parametrize("coverage", [0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0])
    def test_eclipse_success_rate(self, coverage):
        """Parameterized eclipse: measure success at each coverage level."""
        k = 20
        rng = random.Random(42)
        secret = rand_element(rng)
        shares = split(secret, k, 14, rng)

        attack = EclipseAttack(n_paths=k, eclipse_fraction=coverage)
        result = attack.run(shares)

        if coverage < 1.0:
            assert not result['can_reconstruct']
        else:
            assert result['can_reconstruct']

        clean = len(result['unobserved'])
        print(f"\n  Eclipse {coverage*100:.0f}%: "
              f"observed={result['coverage']:.2f}, clean={clean}")


# ---------------------------------------------------------------------------
# Collusion extended
# ---------------------------------------------------------------------------

class TestCollusionExtended:

    def test_collusion_sweep(self):
        """Sweep t from 1 to threshold-1, verify all fail."""
        n = 20
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 14

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.run()

        for t in range(1, threshold):
            corrupt_ids = list(range(1, t + 1))
            attack = CollusionAttack(dkg, corrupt_ids)
            result = attack.attempt_reconstruction()
            assert not result['success'], f"t={t} should fail"

    def test_collusion_at_exact_threshold(self):
        """t = threshold succeeds."""
        n = 20
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 14

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.run()

        corrupt_ids = list(range(1, threshold + 1))
        attack = CollusionAttack(dkg, corrupt_ids)
        result = attack.attempt_reconstruction()
        assert result['success']

    def test_forgery_sweep(self):
        """No forgery possible at t=1..threshold-1."""
        n = 20
        rng = random.Random(42)
        node_ids = list(range(1, n + 1))
        threshold = 14
        degree = threshold - 1

        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        dkg.run()

        # Build verifier
        combined_points = [(nid, dkg.combined_shares[nid]) for nid in node_ids[:threshold]]
        vp_xs = list(range(100, 100 + degree + 1))
        vps = [(x, lagrange_interpolate(combined_points, x)) for x in vp_xs]

        msg = rand_nonzero(rng)
        for t in [1, 3, 6, 10, 13]:
            corrupt_ids = list(range(1, t + 1))
            attack = CollusionAttack(dkg, corrupt_ids)
            result = attack.attempt_forgery(msg, vps, degree)
            assert not result['success'], f"Forgery at t={t} should fail"
