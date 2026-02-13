"""Collusion attack: corrupt nodes share DKG shares.

Tests that t < k/3 corrupt nodes sharing everything
still cannot reconstruct the signing polynomial.
"""

from liun.gf61 import M61, lagrange_interpolate, rand_element
from liun.dkg import DKG


class CollusionAttack:
    """Simulates collusion among corrupt DKG participants.

    Corrupt nodes share all their DKG information and attempt
    to reconstruct the signing polynomial F.
    """

    def __init__(self, dkg: DKG, corrupt_ids: list):
        self.dkg = dkg
        self.corrupt_ids = set(corrupt_ids)

    def collect_shares(self) -> dict:
        """Gather all information available to corrupt nodes.

        Returns dict of what the colluding nodes know.
        """
        knowledge = {
            'own_shares': {},  # combined shares at corrupt positions
            'sent_shares': {},  # shares sent from corrupt nodes to others
            'received_shares': {},  # shares received by corrupt from others
        }

        for cid in self.corrupt_ids:
            if cid in self.dkg.combined_shares:
                knowledge['own_shares'][cid] = self.dkg.combined_shares[cid]

            # Shares the corrupt node sent
            if cid in self.dkg.shares_sent:
                knowledge['sent_shares'][cid] = dict(self.dkg.shares_sent[cid])

            # Shares the corrupt node received from others
            knowledge['received_shares'][cid] = {}
            for sender in self.dkg.node_ids:
                if sender in self.dkg.shares_sent:
                    knowledge['received_shares'][cid][sender] = \
                        self.dkg.shares_sent[sender][cid]

        return knowledge

    def attempt_reconstruction(self) -> dict:
        """Attempt to reconstruct F(0) from colluding knowledge.

        Returns dict with:
            'success': bool - whether reconstruction succeeded
            'n_points': int - number of points available
            'threshold': int - threshold needed
            'attempted_secret': int or None
        """
        knowledge = self.collect_shares()

        # The corrupt nodes know their combined shares: (cid, F(cid))
        known_points = [
            (cid, knowledge['own_shares'][cid])
            for cid in self.corrupt_ids
            if cid in knowledge['own_shares']
        ]

        result = {
            'success': False,
            'n_points': len(known_points),
            'threshold': self.dkg.threshold,
            'attempted_secret': None,
        }

        if len(known_points) >= self.dkg.threshold:
            # Adversary has enough shares!
            secret = lagrange_interpolate(known_points, 0)
            real_secret = self.dkg.get_combined_secret()
            result['success'] = (secret == real_secret)
            result['attempted_secret'] = secret
        else:
            # Try guessing with insufficient shares
            # Even with random guessing, the probability is 1/M61 ≈ 4.3e-19
            result['attempted_secret'] = None

        return result

    def attempt_forgery(self, message: int, verification_points: list,
                        degree: int) -> dict:
        """Attempt to forge a signature on a message.

        Returns dict with success status and attempted sigma.
        """
        from liun.uss import Verifier

        knowledge = self.collect_shares()
        known_points = [
            (cid, knowledge['own_shares'][cid])
            for cid in self.corrupt_ids
            if cid in knowledge['own_shares']
        ]

        # With < threshold points, adversary can only guess
        if len(known_points) < self.dkg.threshold:
            # Random guess
            guessed_sigma = rand_element()
            verifier = Verifier(verification_points, degree)
            return {
                'success': verifier.verify(message, guessed_sigma),
                'sigma': guessed_sigma,
                'method': 'random_guess',
            }
        else:
            # Can compute correct sigma
            sigma = lagrange_interpolate(known_points, message)
            verifier = Verifier(verification_points, degree)
            return {
                'success': verifier.verify(message, sigma),
                'sigma': sigma,
                'method': 'reconstruction',
            }
