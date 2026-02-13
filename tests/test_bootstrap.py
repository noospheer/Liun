"""Tests for multi-path bootstrap protocol."""

import random
import pytest
from liun.bootstrap import (
    ShamirEncoder, BootstrapSession, MultiPathBootstrap, TemporalBootstrap,
)
from liun.gf61 import M61, rand_element
from sim.core.topology import PhysicalTopology, MultiPathBootstrap as TopoBootstrap


class TestShamirEncoder:

    def test_encode_decode_roundtrip(self):
        rng = random.Random(42)
        enc = ShamirEncoder(k=20, threshold=14)
        secret = rand_element(rng)
        shares = enc.encode(secret, rng)
        assert len(shares) == 20
        # Reconstruct from first 14
        assert enc.decode(shares[:14]) == secret

    def test_detect_corrupt_relay(self):
        rng = random.Random(42)
        enc = ShamirEncoder(k=20, threshold=14)
        secret = rand_element(rng)
        shares = enc.encode(secret, rng)
        # Corrupt one share
        x, y = shares[5]
        shares[5] = (x, (y + 1) % M61)
        corrupt = enc.detect_corrupt(shares)
        assert 5 in corrupt


class TestBootstrapSession:

    def test_generate_secrets(self):
        rng = random.Random(42)
        session = BootstrapSession(k=5, rng=rng)
        secrets = session.generate_secrets()
        assert len(secrets) == 5
        assert all(len(s) == 32 for s in secrets)

    def test_derive_psk(self):
        session = BootstrapSession()
        secret = b'\x42' * 32
        psk = session.derive_psk(secret, target_length=256)
        assert len(psk) == 256

    def test_complete(self):
        rng = random.Random(42)
        session = BootstrapSession(k=3, rng=rng)
        session.generate_secrets()
        targets = [10, 20, 30]
        received = {10: b'\x01' * 32, 20: b'\x02' * 32}  # 30 failed
        psks = session.complete(targets, received)
        assert 10 in psks
        assert 20 in psks
        assert 30 not in psks


class TestMultiPathBootstrap:

    def test_bootstrap_no_adversary(self):
        rng = random.Random(42)
        mpb = MultiPathBootstrap(k=5)
        targets = list(range(10, 30))
        result = mpb.bootstrap(targets, rng=rng)
        assert result['success']
        assert result['observed'] == 0
        assert len(result['psks']) == 5

    def test_bootstrap_partial_eclipse(self):
        """Eve observes 3 of 5 paths — bootstrap still succeeds."""
        rng = random.Random(42)
        mpb = MultiPathBootstrap(k=5)
        targets = list(range(10, 30))
        observed_targets = {10, 11, 12}

        result = mpb.bootstrap(
            targets,
            observe_fn=lambda tid, s: tid in observed_targets,
            rng=rng,
        )
        assert result['success']
        assert result['observed'] == 3
        assert result['clean'] == 2

    def test_bootstrap_full_eclipse_fails(self):
        """Eve observes ALL paths — no clean path exists."""
        rng = random.Random(42)
        mpb = MultiPathBootstrap(k=5)
        targets = list(range(10, 30))

        result = mpb.bootstrap(
            targets,
            observe_fn=lambda tid, s: True,
            rng=rng,
        )
        assert not result['success']
        assert result['clean'] == 0

    def test_bootstrap_succeeds_with_one_clean(self):
        """Even 1 clean path is enough."""
        rng = random.Random(42)
        mpb = MultiPathBootstrap(k=20)
        targets = list(range(100, 200))
        # Eve observes all except last
        observed_set = set(targets[:19])

        result = mpb.bootstrap(
            targets,
            observe_fn=lambda tid, s: tid in observed_set,
            rng=rng,
        )
        assert result['success']
        assert result['clean'] == 1


class TestTopologyBootstrap:

    def test_diverse_path_selection(self):
        topo = PhysicalTopology()
        topo.generate_realistic(n_ases=10, routers_per_as=2)
        mpb = TopoBootstrap(topo, k=5)
        targets = mpb.select_targets(0, list(range(1, 10)))
        assert len(targets) <= 5

    def test_eclipse_resistance(self):
        topo = PhysicalTopology()
        topo.generate_realistic(n_ases=10, routers_per_as=3)
        mpb = TopoBootstrap(topo, k=5)

        # Get some routers
        all_routers = list(topo.routers.keys())
        if len(all_routers) >= 10:
            src = all_routers[0]
            dsts = all_routers[5:10]
            eve = {all_routers[3]}  # Eve on one router

            result = mpb.evaluate_eclipse_resistance(src, dsts, eve)
            assert 'total_paths' in result
            assert 'bootstrap_success' in result


class TestTemporalBootstrap:

    def test_multi_session(self):
        tb = TemporalBootstrap(k_per_session=3, n_sessions=3)
        for i in range(3):
            targets = list(range(i * 10, i * 10 + 10))
            tb.run_session(targets, rng=random.Random(i))
        assert tb.total_channels == 9  # 3 sessions * 3 per session


class TestPeerIntro:
    """Test peer introduction protocol (overlay expansion)."""

    def test_xor_psk_one_corrupt_introducer(self):
        """Even with one corrupt introducer, PSK is unknown to Eve."""
        from liun.overlay import PeerIntroduction, OverlayGraph
        g = OverlayGraph()
        for i in range(5):
            g.add_node(i)
            for j in range(i + 1, 5):
                g.add_edge(i, j)

        pi = PeerIntroduction(g)

        # 3 introducers generate components
        rng = random.Random(42)
        components = [bytes(rng.getrandbits(8) for _ in range(32))
                      for _ in range(3)]
        psk = pi.generate_psk(components)

        # Eve knows component[0] (corrupt introducer)
        # But doesn't know components[1] or [2]
        # So Eve cannot reconstruct PSK
        eve_guess = bytes(a for a in components[0])  # Eve only has this
        assert eve_guess != psk  # Eve's knowledge != PSK

    def test_mutual_contacts_sufficient(self):
        from liun.overlay import PeerIntroduction, OverlayGraph
        g = OverlayGraph()
        for i in range(6):
            g.add_node(i)
        # 0-1, 0-2, 0-3, 5-1, 5-2, 5-3
        for m in [1, 2, 3]:
            g.add_edge(0, m)
            g.add_edge(5, m)

        pi = PeerIntroduction(g)
        assert pi.can_introduce(0, 5)
        mutual = pi.find_mutual_contacts(0, 5)
        assert set(mutual) == {1, 2, 3}
