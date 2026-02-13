"""Distributed Key Generation using Shamir over ITS channels.

Implements Protocol 03: collective generation of a threshold signing
polynomial without a trusted dealer. All communication over ITS
(Liu-backed) channels.

Each node generates a random degree-(k-1) polynomial, distributes shares
over channels. Shares are summed to produce a combined signing polynomial
that nobody sees in full.
"""

from liun.gf61 import (
    M61, add, mul, poly_eval_low, rand_element,
    lagrange_interpolate, InterpolatingPoly,
)


class PolynomialContribution:
    """One node's random polynomial contribution to DKG."""

    def __init__(self, node_id: int, degree: int, rng=None):
        self.node_id = node_id
        self.degree = degree
        # coeffs[0] = a_0 (secret), coeffs[d] = a_d
        self.coeffs = [rand_element(rng) for _ in range(degree + 1)]

    @property
    def secret(self) -> int:
        """This node's individual secret: f_i(0)."""
        return self.coeffs[0]

    def compute_share(self, target_id: int) -> int:
        """Compute f_i(target_id) — the share for target_id."""
        return poly_eval_low(self.coeffs, target_id)


class ConsistencyVerifier:
    """Verifies DKG shares via pairwise MAC checks.

    In the real system, this uses ITS channel MACs. In simulation,
    we check algebraic consistency directly.
    """

    def __init__(self, node_ids: list, degree: int):
        self.node_ids = node_ids
        self.degree = degree

    def verify_shares(self, shares_received: dict, contributions: dict) -> list:
        """Verify that shares are consistent with degree-d polynomials.

        shares_received: {from_node: {to_node: share_value}}
        contributions: {node_id: PolynomialContribution} (for honest verification)

        Returns list of detected corrupt node IDs.
        """
        corrupt = []
        for sender_id, share_map in shares_received.items():
            # Check: all shares from this sender lie on a degree-d polynomial
            points = [(target, val) for target, val in share_map.items()]
            if len(points) <= self.degree + 1:
                continue  # Not enough shares to detect inconsistency

            # Build Newton-form polynomial from degree+1 points (O(k^2) once),
            # then evaluate at each remaining point in O(k) each.
            poly = InterpolatingPoly(points[:self.degree + 1])
            for i in range(self.degree + 1, len(points)):
                x, y = points[i]
                if poly.eval_at(x) != y:
                    corrupt.append(sender_id)
                    break

        return corrupt


class ShareCombiner:
    """Combines individual DKG contributions into collective shares."""

    def combine(self, node_id: int, received_shares: dict) -> int:
        """Compute this node's combined share.

        node_id: this node's ID.
        received_shares: {from_node: share_value} where share_value = f_i(node_id).

        Returns: s_j = sum of all f_i(j) mod M61.
        """
        total = 0
        for share_val in received_shares.values():
            total = add(total, share_val)
        return total


class DKG:
    """Orchestrates distributed key generation.

    Runs the full DKG protocol on a set of nodes:
    1. Each node generates a random polynomial
    2. Shares distributed to all other nodes
    3. Consistency verified
    4. Shares combined
    """

    def __init__(self, node_ids: list, threshold: int = None, rng=None):
        self.node_ids = sorted(node_ids)
        self.n = len(node_ids)
        if threshold is None:
            threshold = 2 * self.n // 3 + 1
        self.threshold = threshold
        self.degree = threshold - 1
        self.rng = rng

        self.contributions: dict[int, PolynomialContribution] = {}
        self.shares_sent: dict[int, dict[int, int]] = {}  # from -> {to: val}
        self.combined_shares: dict[int, int] = {}
        self.excluded: set[int] = set()
        self.completed = False

    def generate_contributions(self):
        """Step 1: Each node generates its random polynomial."""
        for nid in self.node_ids:
            self.contributions[nid] = PolynomialContribution(
                nid, self.degree, self.rng
            )

    def distribute_shares(self):
        """Step 2: Each node computes and distributes shares."""
        for sender in self.node_ids:
            self.shares_sent[sender] = {}
            contrib = self.contributions[sender]
            for receiver in self.node_ids:
                self.shares_sent[sender][receiver] = contrib.compute_share(receiver)

    def verify_consistency(self) -> list:
        """Step 3: Verify all shares for consistency.

        Returns list of corrupt node IDs.
        """
        verifier = ConsistencyVerifier(self.node_ids, self.degree)
        corrupt = verifier.verify_shares(self.shares_sent, self.contributions)
        self.excluded = set(corrupt)
        return corrupt

    def combine_shares(self):
        """Step 4: Each honest node combines its received shares."""
        combiner = ShareCombiner()
        for nid in self.node_ids:
            if nid in self.excluded:
                continue
            # Collect shares from non-excluded nodes
            received = {
                sender: self.shares_sent[sender][nid]
                for sender in self.node_ids
                if sender not in self.excluded
            }
            self.combined_shares[nid] = combiner.combine(nid, received)
        self.completed = True

    def run(self, verify: bool = True) -> dict:
        """Run the full DKG protocol.

        Args:
            verify: If True, run consistency verification (O(N^2*k)).
                    Set False for scale benchmarks where verification
                    is already proven correct at smaller N.

        Returns: {node_id: combined_share} for honest nodes.
        """
        self.generate_contributions()
        self.distribute_shares()
        if verify:
            self.verify_consistency()
        self.combine_shares()
        return dict(self.combined_shares)

    def get_combined_secret(self) -> int:
        """Reconstruct F(0) from combined shares (for testing only).

        In production, nobody ever does this.
        """
        if not self.completed:
            raise RuntimeError("DKG not completed")
        honest_ids = [nid for nid in self.node_ids if nid not in self.excluded]
        points = [(nid, self.combined_shares[nid]) for nid in honest_ids[:self.threshold]]
        return lagrange_interpolate(points, 0)

    def inject_corrupt_shares(self, corrupt_id: int, tamper_fn=None):
        """Inject corrupted shares for testing.

        corrupt_id: the node to corrupt.
        tamper_fn: function(receiver_id, original_share) -> tampered_share.
        """
        if tamper_fn is None:
            tamper_fn = lambda recv, s: add(s, 1)
        for receiver in self.node_ids:
            if receiver != corrupt_id:
                original = self.shares_sent[corrupt_id][receiver]
                self.shares_sent[corrupt_id][receiver] = tamper_fn(receiver, original)


class EpochManager:
    """Manages periodic DKG re-deals with fresh randomness."""

    def __init__(self, node_ids: list, threshold: int = None):
        self.node_ids = node_ids
        self.threshold = threshold
        self.epoch = 0
        self.history: list[DKG] = []

    def new_epoch(self, rng=None) -> DKG:
        """Run a new DKG for the next epoch."""
        dkg = DKG(self.node_ids, self.threshold, rng)
        dkg.run()
        self.history.append(dkg)
        self.epoch += 1
        return dkg

    @property
    def current_dkg(self) -> DKG:
        return self.history[-1] if self.history else None
