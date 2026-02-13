"""Liun node: ties all components together.

A node participates in the Liun network by:
1. Bootstrapping (Protocol 01) or receiving a PSK
2. Establishing Liu channels (Protocol 05)
3. Expanding via peer introduction (Protocol 02)
4. Participating in DKG (Protocol 03)
5. Signing and verifying (Protocol 04)
"""

from liun.liu_channel import LiuChannel, ChannelTable
from liun.uss import PartialSigner, Verifier, SignatureCombiner, DisputeResolver
from liun.overlay import personalized_pagerank, OverlayGraph


class LiunNode:
    """Main entry point for a Liun participant."""

    def __init__(self, node_id: int):
        self.node_id = node_id
        self.channels = ChannelTable()
        self.signing_share: int = None
        self.partial_signer: PartialSigner = None
        self.verifier: Verifier = None
        self.trust_scores: dict = {}
        self.overlay: OverlayGraph = None

    def init_channel(self, peer_id: int, psk: bytes, mock=None):
        """Initialize an ITS channel with a peer."""
        ch = LiuChannel(peer_id, psk, mock_channel=mock)
        self.channels.add(ch)
        return ch

    def participate_dkg(self, share_y: int, verification_points: list,
                        degree: int):
        """Set up signing capability from DKG results."""
        self.signing_share = share_y
        self.partial_signer = PartialSigner(self.node_id, share_y)
        self.verifier = Verifier(verification_points, degree)

    def sign(self, message: int, committee_ids: list) -> int:
        """Produce a partial threshold signature."""
        if self.partial_signer is None:
            raise RuntimeError("Node not initialized for signing")
        return self.partial_signer.partial_sign(message, committee_ids)

    def verify(self, message: int, sigma: int) -> bool:
        """Verify a signature against held verification points."""
        if self.verifier is None:
            raise RuntimeError("Node not initialized for verification")
        return self.verifier.verify(message, sigma)

    def compute_trust(self, overlay: OverlayGraph = None):
        """Compute trust scores via personalized PageRank."""
        g = overlay or self.overlay
        if g is None:
            return {}
        self.trust_scores = personalized_pagerank(self.node_id, g)
        return self.trust_scores

    @staticmethod
    def combine_signatures(partials: list) -> int:
        """Combine partial signatures into full signature."""
        combiner = SignatureCombiner()
        return combiner.combine(partials)

    @staticmethod
    def resolve_dispute(message: int, sigma: int, verifiers: list) -> str:
        """Resolve a signature dispute via majority adjudication."""
        resolver = DisputeResolver()
        return resolver.resolve(message, sigma, verifiers)
