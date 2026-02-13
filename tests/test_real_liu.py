"""Tests for real Liu protocol integration via liuproto.StreamPipe.

All tests marked @pytest.mark.slow since real physics (Gaussian noise
exchange + Toeplitz hashing) is ~100-500x slower than mock channels.
"""

import random
import pytest
from liun.gf61 import M61, rand_element, lagrange_interpolate
from liun.dkg import DKG
from liun.uss import PartialSigner, SignatureCombiner, Verifier
from sim.core.liu_adapter import RealLiuChannel
from sim.core.mock_liu import MockLiuChannel


@pytest.fixture(autouse=True)
def reset_pipe_registry():
    """Clear shared StreamPipe registry between tests."""
    RealLiuChannel.reset()
    yield
    RealLiuChannel.reset()


@pytest.fixture
def sample_psk():
    """A deterministic 256-byte PSK for testing."""
    r = random.Random(99)
    return bytes(r.getrandbits(8) for _ in range(256))


@pytest.mark.slow
class TestRealLiuChannel:

    def test_key_generation(self, sample_psk):
        """Real key bytes are nonzero and not constant."""
        ch = RealLiuChannel(0, 1, sample_psk)
        bits = ch.generate_key_bits(256)
        assert len(bits) == 32
        assert bits != b'\x00' * 32
        # Not all the same byte
        assert len(set(bits)) > 1
        assert ch.total_bits_generated == 256

    def test_key_agreement(self, sample_psk):
        """Alice and Bob get identical bytes from shared StreamPipe."""
        alice = RealLiuChannel(0, 1, sample_psk)
        bob = RealLiuChannel(1, 0, sample_psk)
        # Both share the same pipe; buffers contain identical bytes
        ka = alice.generate_key_bits(128)
        kb = bob.generate_key_bits(128)
        assert ka == kb

    def test_mac_authenticate_verify(self, sample_psk):
        """Compute + verify MAC with PSK-derived keys."""
        ch = RealLiuChannel(0, 1, sample_psk)
        data = [42, 1337, 7, 999]
        tag = ch.authenticate(data)
        assert isinstance(tag, int)
        assert 0 <= tag < M61
        assert ch.verify_mac(data, tag)

    def test_mac_reject_tamper(self, sample_psk):
        """Tampered data fails MAC verification."""
        ch = RealLiuChannel(0, 1, sample_psk)
        data = [42, 1337, 7, 999]
        tag = ch.authenticate(data)
        tampered = [42, 1338, 7, 999]
        assert not ch.verify_mac(tampered, tag)

    def test_channel_lifecycle(self, sample_psk):
        """generate -> authenticate -> advance_run -> close."""
        ch = RealLiuChannel(0, 1, sample_psk)
        assert ch.active
        assert ch.channel_id == (0, 1)

        # Generate key material
        bits = ch.generate_key_bits(64)
        assert len(bits) == 8

        # Authenticate
        data = [1, 2, 3]
        tag0 = ch.authenticate(data, run_idx=0)
        assert ch.verify_mac(data, tag0, run_idx=0)

        # Advance run -> different keys
        ch.advance_run()
        assert ch.run_idx == 1
        tag1 = ch.authenticate(data)
        assert tag0 != tag1  # different run_idx -> different keys

        # Close
        ch.close()
        assert not ch.active
        with pytest.raises(RuntimeError):
            ch.generate_key_bits(8)

    def test_multiple_key_requests(self, sample_psk):
        """Can request key material multiple times."""
        ch = RealLiuChannel(0, 1, sample_psk)
        k1 = ch.generate_key_bits(128)
        k2 = ch.generate_key_bits(128)
        # Sequential reads should yield different bytes (consumed from buffer)
        assert k1 != k2


@pytest.mark.slow
class TestRealLiuDKG:

    def test_n10_dkg_real_liu(self):
        """N=10 DKG with real Liu channels, shares consistent."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        shares = dkg.run()

        assert len(shares) == 10
        secret = dkg.get_combined_secret()

        # Verify using different subsets
        points = [(nid, shares[nid]) for nid in node_ids]
        subset1 = points[:dkg.threshold]
        subset2 = points[3:3 + dkg.threshold]
        assert lagrange_interpolate(subset1, 0) == secret
        assert lagrange_interpolate(subset2, 0) == secret

        # Now authenticate shares over real Liu channels
        psk = bytes(rng.getrandbits(8) for _ in range(256))
        ch = RealLiuChannel(1, 2, psk)
        data = [shares[1], shares[2]]
        tag = ch.authenticate(data)
        assert ch.verify_mac(data, tag)

    def test_n10_signing_real_liu(self):
        """Threshold sign + verify using real key material for MAC."""
        rng = random.Random(42)
        n = 10
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

        # Verify
        basis_points = [(nid, shares[nid]) for nid in committee]
        vp_xs = list(range(n + 100, n + 100 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        verifier = Verifier(vps, degree)
        assert verifier.verify(message, sigma)

        # Authenticate the signature over a real Liu channel
        psk = bytes(rng.getrandbits(8) for _ in range(256))
        ch = RealLiuChannel(1, 2, psk)
        tag = ch.authenticate([message, sigma])
        assert ch.verify_mac([message, sigma], tag)


@pytest.mark.slow
class TestRealLiuNetwork:

    def test_sim_network_real_liu(self):
        """SimNetwork(5, use_real_liu=True) initializes."""
        from sim.network.sim_network import SimNetwork
        net = SimNetwork(5, 'random', seed=42, use_real_liu=True)
        assert len(net.nodes) == 5
        assert net.n_channels > 0
        # Every node has real Liu channels
        for node in net.nodes.values():
            assert len(node.channels) > 0
            for ch in node.channels.values():
                assert isinstance(ch, RealLiuChannel)

    def test_messages_route_real(self):
        """Send/receive messages over a real-Liu network."""
        from sim.network.sim_network import SimNetwork
        net = SimNetwork(5, 'random', seed=42, use_real_liu=True)
        node0 = net.nodes[0]
        if node0.neighbors:
            peer = next(iter(node0.neighbors))
            net.send(0, peer, 'test', {'data': 42})
            net.tick(1)
            assert len(net.nodes[peer].inbox) == 1
            assert net.nodes[peer].inbox[0].payload['data'] == 42


@pytest.mark.slow
class TestRealVsMock:

    def test_mac_cross_check(self, sample_psk):
        """RealLiuChannel MAC matches MockLiuChannel MAC for same inputs."""
        data = [100, 200, 300, 400, 500]
        real_ch = RealLiuChannel(0, 1, sample_psk)
        mock_ch = MockLiuChannel(0, 1, sample_psk)

        for run_idx in range(5):
            real_tag = real_ch.authenticate(data, run_idx=run_idx)
            mock_tag = mock_ch.authenticate(data, run_idx=run_idx)
            assert real_tag == mock_tag, (
                f"MAC mismatch at run_idx={run_idx}: real={real_tag}, mock={mock_tag}")

    def test_protocol_equivalence(self):
        """Same DKG/sign protocol with both backends yields same algebraic properties."""
        rng = random.Random(42)
        n = 10
        node_ids = list(range(1, n + 1))
        threshold = 2 * n // 3 + 1
        degree = threshold - 1

        # DKG is independent of channel backend (pure GF61 math)
        dkg = DKG(node_ids, threshold=threshold, rng=rng)
        shares = dkg.run()
        secret = dkg.get_combined_secret()

        message = rand_element(random.Random(99))
        committee = node_ids[:threshold]
        signers = [PartialSigner(nid, shares[nid]) for nid in committee]
        partials = [s.partial_sign(message, committee) for s in signers]
        sigma = SignatureCombiner().combine(partials)

        basis_points = [(nid, shares[nid]) for nid in committee]
        vp_xs = list(range(n + 100, n + 100 + degree + 1))
        vps = [(x, lagrange_interpolate(basis_points, x)) for x in vp_xs]
        verifier = Verifier(vps, degree)
        assert verifier.verify(message, sigma)

        # Now verify MACs are consistent across both backends
        psk = bytes(random.Random(77).getrandbits(8) for _ in range(256))
        real_ch = RealLiuChannel(1, 2, psk)
        mock_ch = MockLiuChannel(1, 2, psk)

        mac_data = [message, sigma, secret]
        assert real_ch.authenticate(mac_data) == mock_ch.authenticate(mac_data)
