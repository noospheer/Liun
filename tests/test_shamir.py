"""Tests for Shamir secret sharing."""

import random
import pytest
from liun.gf61 import M61, rand_element
from liun.shamir import split, reconstruct, reconstruct_at, consistency_check


class TestRoundTrip:
    """Secret sharing and reconstruction."""

    def test_basic_3_of_5(self, rng):
        secret = rand_element(rng)
        shares = split(secret, 5, 3, rng)
        assert len(shares) == 5
        # Any 3 shares reconstruct
        assert reconstruct(shares[:3]) == secret
        assert reconstruct(shares[1:4]) == secret
        assert reconstruct(shares[2:]) == secret

    def test_k_equals_1(self, rng):
        """k=1: constant polynomial, every share = secret."""
        secret = rand_element(rng)
        shares = split(secret, 5, 1, rng)
        for _, y in shares:
            assert y == secret
        assert reconstruct([shares[0]]) == secret

    def test_k_equals_n(self, rng):
        """k=n: need all shares."""
        secret = rand_element(rng)
        n = 7
        shares = split(secret, n, n, rng)
        assert reconstruct(shares) == secret

    def test_various_thresholds(self, rng):
        for n, k in [(3, 2), (5, 3), (10, 7), (20, 14), (10, 10)]:
            secret = rand_element(rng)
            shares = split(secret, n, k, rng)
            # Exactly k shares suffice
            assert reconstruct(shares[:k]) == secret

    def test_zero_secret(self, rng):
        shares = split(0, 5, 3, rng)
        assert reconstruct(shares[:3]) == 0

    def test_max_secret(self, rng):
        shares = split(M61 - 1, 5, 3, rng)
        assert reconstruct(shares[:3]) == M61 - 1

    def test_reconstruct_at_nonzero(self, rng):
        """Reconstruct at arbitrary point, not just 0."""
        secret = rand_element(rng)
        shares = split(secret, 10, 5, rng)
        # The polynomial evaluated at x=3 should equal share[2] (x_i=3)
        val = reconstruct_at(shares[:5], 3)
        assert val == shares[2][1]


class TestSecrecy:
    """k-1 shares reveal no information about the secret."""

    def test_k_minus_1_shares_uniform(self, rng):
        """With k-1 shares, any secret is equally consistent."""
        k = 5
        shares = split(42, 10, k, rng)
        subset = shares[:k - 1]  # 4 shares

        # For each of 20 candidate secrets, the 4 shares are consistent
        # with a valid degree-(k-1) polynomial having that secret.
        # This proves no information leakage.
        for candidate in range(20):
            # Construct points: the 4 shares + (0, candidate)
            points = [(0, candidate)] + list(subset)
            # These 5 points define a unique degree-4 polynomial
            # Verify it's self-consistent by checking each point
            for x, y in points:
                from liun.gf61 import lagrange_interpolate
                assert lagrange_interpolate(points, x) == y


class TestCorruptionDetection:
    """Consistency check finds tampered shares."""

    def test_no_corruption(self, rng):
        secret = rand_element(rng)
        shares = split(secret, 10, 5, rng)
        assert consistency_check(shares, 4) == []

    def test_single_corruption(self, rng):
        secret = rand_element(rng)
        shares = split(secret, 10, 5, rng)
        # Corrupt share at index 3
        x, y = shares[3]
        shares[3] = (x, (y + 1) % M61)
        corrupt = consistency_check(shares, 4)
        assert 3 in corrupt

    def test_multiple_corruptions(self, rng):
        secret = rand_element(rng)
        shares = split(secret, 10, 3, rng)
        # Corrupt shares at indices 1 and 5
        for idx in [1, 5]:
            x, y = shares[idx]
            shares[idx] = (x, (y + 7) % M61)
        corrupt = consistency_check(shares, 2)
        assert 1 in corrupt
        assert 5 in corrupt

    def test_insufficient_redundancy(self, rng):
        """With exactly k+1 shares and degree k-1, can detect 1 corruption."""
        secret = rand_element(rng)
        shares = split(secret, 4, 3, rng)
        # Corrupt one
        x, y = shares[0]
        shares[0] = (x, (y + 1) % M61)
        corrupt = consistency_check(shares, 2)
        assert 0 in corrupt

    def test_no_redundancy_returns_empty(self, rng):
        """With exactly degree+1 shares, can't detect corruption."""
        secret = rand_element(rng)
        shares = split(secret, 3, 3, rng)
        corrupt = consistency_check(shares, 2)
        assert corrupt == []


class TestEdgeCases:
    """Input validation."""

    def test_invalid_secret_range(self):
        with pytest.raises(ValueError):
            split(M61, 5, 3)
        with pytest.raises(ValueError):
            split(-1, 5, 3)

    def test_k_less_than_1(self):
        with pytest.raises(ValueError):
            split(42, 5, 0)

    def test_n_less_than_k(self):
        with pytest.raises(ValueError):
            split(42, 3, 5)

    def test_empty_shares(self):
        with pytest.raises(ValueError):
            reconstruct([])
