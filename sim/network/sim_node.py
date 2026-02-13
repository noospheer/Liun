"""Simulated Liun node wrapping real protocol logic.

Each SimNode holds:
- Signing share (from DKG)
- Verification points (for USS)
- Trust scores (from PageRank)
- Channel table (MockLiuChannels)
"""

import random as _random
from liun.gf61 import rand_element
from liun.uss import PartialSigner, Verifier, SignatureCombiner
from sim.core.mock_liu import create_channel


class SimNode:
    """A simulated Liun node with real protocol logic."""

    def __init__(self, node_id: int, rng=None):
        self.node_id = node_id
        self.rng = rng or _random.Random(node_id)
        self.channels: dict = {}  # peer_id -> MockLiuChannel or RealLiuChannel
        self.neighbors: set[int] = set()

        # DKG state
        self.signing_share: int = None  # F(node_id)
        self.dkg_contributions: dict[int, int] = {}  # from_node -> share value

        # USS state
        self.partial_signer: PartialSigner = None
        self.verifier: Verifier = None
        self.verification_points: list = []

        # Trust state
        self.trust_scores: dict[int, float] = {}

        # Message inbox
        self.inbox: list = []

        # Corruption flag (for adversary)
        self.corrupt = False

    def establish_channel(self, peer_id: int, psk: bytes,
                          use_real_liu: bool = False):
        """Create a Liu channel to a peer (mock or real)."""
        ch = create_channel(self.node_id, peer_id, psk,
                            use_real=use_real_liu)
        self.channels[peer_id] = ch
        self.neighbors.add(peer_id)
        return ch

    def receive_message(self, msg):
        """Handle incoming message from the bus."""
        self.inbox.append(msg)

    def set_signing_share(self, share_y: int):
        """Set this node's signing share from DKG."""
        self.signing_share = share_y
        self.partial_signer = PartialSigner(self.node_id, share_y)

    def set_verification_points(self, points: list, degree: int):
        """Set verification points for USS."""
        self.verification_points = points
        self.verifier = Verifier(points, degree)

    def partial_sign(self, message: int, committee_ids: list) -> int:
        """Produce a partial signature."""
        if self.partial_signer is None:
            raise RuntimeError(f"Node {self.node_id} has no signing share")
        return self.partial_signer.partial_sign(message, committee_ids)

    def verify(self, message: int, sigma: int) -> bool:
        """Verify a signature."""
        if self.verifier is None:
            raise RuntimeError(f"Node {self.node_id} has no verifier")
        return self.verifier.verify(message, sigma)

    @property
    def degree(self) -> int:
        """Number of channels / neighbors."""
        return len(self.neighbors)
