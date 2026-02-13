"""Tests for Distributed Key Generation."""

import random
import pytest
from liun.gf61 import M61, add, lagrange_interpolate, rand_element
from liun.dkg import DKG, EpochManager


class TestDKGBasic:

    def test_n10_produces_consistent_shares(self):
        """10 nodes produce combined shares that reconstruct the same secret."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        shares = dkg.run()

        assert len(shares) == 10
        # All honest nodes can reconstruct the same F(0)
        secret = dkg.get_combined_secret()

        # Verify using different subsets
        points = [(nid, shares[nid]) for nid in node_ids]
        subset1 = points[:dkg.threshold]
        subset2 = points[3:3 + dkg.threshold]
        assert lagrange_interpolate(subset1, 0) == secret
        assert lagrange_interpolate(subset2, 0) == secret

    def test_combined_polynomial_is_sum(self):
        """Combined share at j = sum of all f_i(j)."""
        rng = random.Random(99)
        node_ids = list(range(1, 6))
        dkg = DKG(node_ids, threshold=3, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()
        dkg.verify_consistency()
        dkg.combine_shares()

        for nid in node_ids:
            expected = 0
            for sender in node_ids:
                expected = add(expected, dkg.shares_sent[sender][nid])
            assert dkg.combined_shares[nid] == expected

    def test_no_single_node_knows_polynomial(self):
        """Each node only knows its own combined share, not F(0)."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        dkg.run()
        secret = dkg.get_combined_secret()

        # No node's individual contribution secret equals the combined secret
        for nid in node_ids:
            assert dkg.contributions[nid].secret != secret

    def test_k_minus_1_shares_reveal_nothing(self):
        """k-1 shares are consistent with any possible secret."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        dkg.run()

        # Take k-1 shares
        subset = [(nid, dkg.combined_shares[nid]) for nid in node_ids[:dkg.threshold - 1]]
        # Any candidate secret is consistent
        for candidate in range(10):
            points = [(0, candidate)] + subset
            # These define a unique polynomial — no contradiction
            for x, y in points:
                assert lagrange_interpolate(points, x) == y


class TestDKGCorruptDetection:

    def test_corrupt_node_detected(self):
        """A node sending inconsistent shares is detected."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()

        # Corrupt node 3's shares
        dkg.inject_corrupt_shares(3)

        corrupt = dkg.verify_consistency()
        assert 3 in corrupt

    def test_honest_nodes_reconstruct_after_exclusion(self):
        """After excluding corrupt node, honest nodes still agree."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()
        dkg.inject_corrupt_shares(5)
        dkg.verify_consistency()
        dkg.combine_shares()

        # Honest nodes should agree on the combined secret
        honest = [nid for nid in node_ids if nid not in dkg.excluded]
        assert 5 not in honest
        points = [(nid, dkg.combined_shares[nid]) for nid in honest[:dkg.threshold]]
        secret = lagrange_interpolate(points, 0)

        # Verify with a different subset of honest nodes
        points2 = [(nid, dkg.combined_shares[nid]) for nid in honest[-dkg.threshold:]]
        assert lagrange_interpolate(points2, 0) == secret

    def test_multiple_corrupt_detected(self):
        """Multiple corrupt nodes detected."""
        rng = random.Random(42)
        node_ids = list(range(1, 11))
        dkg = DKG(node_ids, rng=rng)
        dkg.generate_contributions()
        dkg.distribute_shares()
        dkg.inject_corrupt_shares(2)
        dkg.inject_corrupt_shares(7)
        corrupt = dkg.verify_consistency()
        assert 2 in corrupt
        assert 7 in corrupt


class TestDKGScale:

    def test_n100_dkg(self):
        """DKG with 100 nodes produces consistent shares."""
        rng = random.Random(42)
        node_ids = list(range(1, 101))
        dkg = DKG(node_ids, rng=rng)
        shares = dkg.run()
        assert len(shares) == 100

        # Verify consistency: two random subsets reconstruct same secret
        secret = dkg.get_combined_secret()
        import random as r2
        r2_rng = r2.Random(99)
        subset = r2_rng.sample(node_ids, dkg.threshold)
        points = [(nid, shares[nid]) for nid in subset]
        assert lagrange_interpolate(points, 0) == secret


class TestEpochManager:

    def test_epoch_rotation(self):
        """Epoch manager runs multiple DKGs."""
        node_ids = list(range(1, 11))
        em = EpochManager(node_ids)
        dkg1 = em.new_epoch(random.Random(1))
        dkg2 = em.new_epoch(random.Random(2))

        assert em.epoch == 2
        # Different epochs produce different secrets
        assert dkg1.get_combined_secret() != dkg2.get_combined_secret()
        assert em.current_dkg is dkg2
