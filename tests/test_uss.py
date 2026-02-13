"""Tests for USS threshold signatures."""

import random
import pytest
from liun.gf61 import M61, rand_element, rand_nonzero
from liun.uss import (
    SigningPolynomial, PartialSigner, SignatureCombiner,
    Verifier, DisputeResolver, SignatureBudget,
)


class TestDirectSigning:
    """Full polynomial signing (testing aid, not threshold)."""

    def test_sign_verify_basic(self, rng):
        degree = 10
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        # Verifier with degree+1 verification points
        vp_xs = [rand_nonzero(rng) for _ in range(degree + 1)]
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)
        assert v.verify(msg, sigma)

    def test_wrong_sigma_fails(self, rng):
        degree = 10
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        vp_xs = [rand_nonzero(rng) for _ in range(degree + 1)]
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)

        # Wrong sigma
        bad_sigma = (sigma + 1) % M61
        assert not v.verify(msg, bad_sigma)

    def test_different_messages_different_sigs(self, rng):
        poly = SigningPolynomial(10, rng)
        m1, m2 = rand_nonzero(rng), rand_nonzero(rng)
        assert poly.sign(m1) != poly.sign(m2) or m1 == m2


class TestThresholdSigning:
    """k partial signers combine to produce valid signature."""

    def test_k_partials_combine(self, rng):
        degree = 6
        n_nodes = 10
        k = 7  # threshold

        poly = SigningPolynomial(degree, rng)
        node_ids = list(range(1, n_nodes + 1))

        # Create partial signers from shares
        signers = []
        for nid in node_ids:
            _, share_y = poly.get_share(nid)
            signers.append(PartialSigner(nid, share_y))

        # Sign a message with first k signers
        msg = rand_nonzero(rng)
        committee = node_ids[:k]
        partials = [s.partial_sign(msg, committee) for s in signers[:k]]

        combiner = SignatureCombiner()
        sigma = combiner.combine(partials)

        # Should equal F(msg)
        expected = poly.sign(msg)
        assert sigma == expected

    def test_different_committees_same_signature(self, rng):
        """Any committee of k nodes produces the same final signature."""
        degree = 4
        n_nodes = 8
        k = 5

        poly = SigningPolynomial(degree, rng)
        node_ids = list(range(1, n_nodes + 1))

        signers = []
        for nid in node_ids:
            _, share_y = poly.get_share(nid)
            signers.append(PartialSigner(nid, share_y))

        msg = rand_nonzero(rng)
        combiner = SignatureCombiner()

        # Committee 1: first k
        c1 = node_ids[:k]
        p1 = [signers[i].partial_sign(msg, c1) for i in range(k)]
        sig1 = combiner.combine(p1)

        # Committee 2: last k
        c2 = node_ids[-k:]
        p2 = [signers[n_nodes - k + i].partial_sign(msg, c2) for i in range(k)]
        sig2 = combiner.combine(p2)

        assert sig1 == sig2

    def test_k_minus_1_partials_cannot_forge(self, rng):
        """k-1 partial signatures don't help forge for a new message."""
        degree = 6
        n_nodes = 10
        k = 7

        poly = SigningPolynomial(degree, rng)
        node_ids = list(range(1, n_nodes + 1))

        signers = []
        for nid in node_ids:
            _, share_y = poly.get_share(nid)
            signers.append(PartialSigner(nid, share_y))

        # Adversary has k-1 signers
        msg = rand_nonzero(rng)
        committee_partial = node_ids[:k - 1]

        # With only k-1 partials, adversary tries guessing the missing partial
        partials = [s.partial_sign(msg, node_ids[:k]) for s in signers[:k - 1]]
        # Add a random "guess" for the k-th partial
        partials.append(rand_element(rng))

        combiner = SignatureCombiner()
        forged_sigma = combiner.combine(partials)

        # Verify with enough verification points
        vp_xs = list(range(n_nodes + 100, n_nodes + 100 + degree + 1))
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)

        # Forged signature should (almost certainly) fail
        assert not v.verify(msg, forged_sigma)


class TestVerification:
    """Verification with various numbers of verification points."""

    def test_sufficient_verification_points(self, rng):
        degree = 8
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        # d/2 + 1 verification points (enough to over-determine with sigma)
        n_vps = degree // 2 + 1
        vp_xs = list(range(1000, 1000 + n_vps))
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)
        assert v.verify(msg, sigma)

    def test_insufficient_points_accepts_anything(self, rng):
        """With too few points, can't disprove anything."""
        degree = 10
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)

        # Only 2 verification points for degree 10 (need 11 total to over-determine)
        vp_xs = [1000, 1001]
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)
        # Even a random sigma "passes" — not enough constraint
        assert v.verify(msg, rand_element(rng))

    def test_forgery_with_wrong_sigma_detected(self, rng):
        degree = 6
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)

        # degree + 1 verification points (maximally over-determined)
        vp_xs = list(range(2000, 2000 + degree + 1))
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)

        # Correct sigma passes
        sigma = poly.sign(msg)
        assert v.verify(msg, sigma)

        # Wrong sigma fails
        assert not v.verify(msg, (sigma + 1) % M61)


class TestDisputeResolution:

    def test_valid_signature_resolved(self, rng):
        degree = 6
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        sigma = poly.sign(msg)

        # Create 5 verifiers with different verification points
        verifiers = []
        for i in range(5):
            base = 3000 + i * (degree + 2)
            vp_xs = list(range(base, base + degree + 1))
            vps = poly.get_verification_points(vp_xs)
            verifiers.append(Verifier(vps, degree))

        resolver = DisputeResolver()
        assert resolver.resolve(msg, sigma, verifiers) == 'valid'

    def test_forged_signature_detected(self, rng):
        degree = 6
        poly = SigningPolynomial(degree, rng)
        msg = rand_nonzero(rng)
        bad_sigma = rand_element(rng)

        verifiers = []
        for i in range(5):
            base = 4000 + i * (degree + 2)
            vp_xs = list(range(base, base + degree + 1))
            vps = poly.get_verification_points(vp_xs)
            verifiers.append(Verifier(vps, degree))

        resolver = DisputeResolver()
        assert resolver.resolve(msg, bad_sigma, verifiers) == 'forged'


class TestSignatureBudget:

    def test_budget_tracking(self):
        budget = SignatureBudget(degree=100)
        assert budget.max_signatures == 50
        assert budget.remaining == 50
        assert budget.can_sign()

        for i in range(1, 51):
            budget.record(i)
        assert not budget.can_sign()
        assert budget.remaining == 0

    def test_duplicate_messages_not_double_counted(self):
        budget = SignatureBudget(degree=10)
        budget.record(42)
        budget.record(42)
        assert budget.used == 1

    def test_all_forgery_strategies_fail(self, rng):
        """Adversary with <k shares fails all strategies."""
        degree = 8
        k = degree + 1  # need degree+1 points to reconstruct
        n_nodes = 15

        poly = SigningPolynomial(degree, rng)

        # Adversary controls k-1 nodes
        adversary_ids = list(range(1, k))
        adversary_shares = poly.get_shares(adversary_ids)

        # Verifier setup
        vp_xs = list(range(5000, 5000 + degree + 1))
        vps = poly.get_verification_points(vp_xs)
        v = Verifier(vps, degree)

        target_msg = rand_nonzero(rng)
        real_sigma = poly.sign(target_msg)

        # Strategy 1: Random guess
        for _ in range(10):
            assert not v.verify(target_msg, rand_element(rng)) or \
                rand_element(rng) == real_sigma

        # Strategy 2: Interpolate from k-1 shares + guess the secret
        # Adversary knows k-1 points on F, guesses F(0) to get k points
        from liun.gf61 import lagrange_interpolate
        for _ in range(10):
            guess_secret = rand_element(rng)
            # Construct k points: the k-1 shares + (0, guess)
            trial_points = [(0, guess_secret)] + adversary_shares
            trial_sigma = lagrange_interpolate(trial_points, target_msg)
            if trial_sigma == real_sigma:
                continue  # Astronomically unlikely
            assert not v.verify(target_msg, trial_sigma)
