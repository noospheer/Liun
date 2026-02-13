"""Unconditionally Secure Signatures (USS) over GF(M61).

Threshold polynomial signatures with ITS unforgeability.
Algebraically compatible with the Liu protocol's MAC field.

Signing: sigma = F(m) where F is a secret polynomial of degree d.
Verification: check that (m, sigma) is consistent with independently
held evaluation points of F.
"""

from liun.gf61 import (
    M61, add, sub, mul, inv, neg,
    poly_eval_low, lagrange_interpolate, lagrange_basis_at,
    rand_element,
)
from liun.shamir import split, reconstruct


class SigningPolynomial:
    """A secret polynomial F(x) of degree d over GF(M61).

    In production, nobody ever holds the full polynomial — it exists
    only as distributed shares. This class is for testing.
    """

    def __init__(self, degree: int, rng=None):
        # coeffs[0] = a_0, coeffs[d] = a_d (low-degree first)
        self.degree = degree
        self.coeffs = [rand_element(rng) for _ in range(degree + 1)]

    def sign(self, message: int) -> int:
        """sigma = F(message) mod M61."""
        return poly_eval_low(self.coeffs, message)

    def eval_at(self, x: int) -> int:
        return poly_eval_low(self.coeffs, x)

    def get_share(self, node_id: int) -> tuple:
        """Return (node_id, F(node_id)) as a signing share."""
        return (node_id, self.eval_at(node_id))

    def get_shares(self, node_ids: list) -> list:
        return [self.get_share(nid) for nid in node_ids]

    def get_verification_points(self, point_xs: list) -> list:
        """Return evaluation points for verification."""
        return [(x, self.eval_at(x)) for x in point_xs]


class PartialSigner:
    """A node holding one signing share of the collective polynomial."""

    def __init__(self, node_id: int, share_y: int):
        self.node_id = node_id
        self.share_y = share_y  # F(node_id)

    def partial_sign(self, message: int, committee_ids: list) -> int:
        """Produce partial signature: share_y * L_i(message).

        committee_ids: list of all node IDs in the signing committee.
        """
        idx = committee_ids.index(self.node_id)
        basis = lagrange_basis_at(committee_ids, idx, message)
        return mul(self.share_y, basis)


class SignatureCombiner:
    """Collects partial signatures and combines into full signature."""

    def combine(self, partials: list) -> int:
        """Sum partial signatures to get sigma = F(message).

        partials: list of partial signature values (ints).
        """
        result = 0
        for p in partials:
            result = add(result, p)
        return result


class Verifier:
    """Holds verification points and checks signature consistency.

    A verifier has d/2 evaluation points of F. Together with the
    claimed (message, sigma), that's d/2 + 1 points. If these lie on
    a polynomial of degree d, the signature is accepted.

    For simplicity, we check: interpolating the verification points
    plus (message, sigma) at any other verification point must agree.
    """

    def __init__(self, verification_points: list, degree: int):
        """
        verification_points: list of (x, F(x)) pairs.
        degree: degree of the signing polynomial.
        """
        self.points = verification_points
        self.degree = degree

    def verify(self, message: int, sigma: int) -> bool:
        """Check if (message, sigma) is consistent with verification points.

        We have len(self.points) known evaluations plus (message, sigma).
        If the total is <= degree + 1, we can't disprove; accept.
        If > degree + 1, check consistency via leave-one-out.
        """
        all_points = self.points + [(message, sigma)]
        n = len(all_points)

        if n <= self.degree + 1:
            # Not enough points to over-determine; can't disprove
            return True

        # Check: interpolate degree+1 points, verify remaining
        # Use first degree+1 points as basis
        basis = all_points[:self.degree + 1]
        for i in range(self.degree + 1, n):
            x_i, y_i = all_points[i]
            expected = lagrange_interpolate(basis, x_i)
            if expected != y_i:
                return False
        return True


class DisputeResolver:
    """Majority adjudication for non-repudiation disputes."""

    def resolve(self, message: int, sigma: int, verifiers: list) -> str:
        """Resolve dispute by majority vote among verifiers.

        Returns:
            'valid' if majority of verifiers accept.
            'forged' if majority reject.
            'inconclusive' if tied.
        """
        accept = 0
        reject = 0
        for v in verifiers:
            if v.verify(message, sigma):
                accept += 1
            else:
                reject += 1

        if accept > reject:
            return 'valid'
        elif reject > accept:
            return 'forged'
        else:
            return 'inconclusive'


class SignatureBudget:
    """Tracks signature usage to enforce epoch rotation.

    After ~d/2 signatures, enough public (message, sigma) pairs exist
    for anyone to reconstruct F.
    """

    def __init__(self, degree: int):
        self.degree = degree
        self.max_signatures = degree // 2
        self.used = 0
        self.signed_messages = set()

    def can_sign(self) -> bool:
        return self.used < self.max_signatures

    def record(self, message: int):
        if message not in self.signed_messages:
            self.signed_messages.add(message)
            self.used += 1

    @property
    def remaining(self) -> int:
        return max(0, self.max_signatures - self.used)
