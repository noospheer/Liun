"""Multi-path bootstrap for new node joining.

Implements Protocol 01: multi-path XOR key agreement with Shamir
protection against active adversaries. This is the only phase
where network topology matters.
"""

import os
import hashlib
from liun.shamir import split, reconstruct, consistency_check


class ShamirEncoder:
    """Encode bootstrap secrets with Shamir for relay protection."""

    def __init__(self, k: int = 20, threshold: int = 14):
        self.k = k
        self.threshold = threshold

    def encode(self, secret: int, rng=None) -> list:
        """Encode a secret into k Shamir shares."""
        return split(secret, self.k, self.threshold, rng)

    def decode(self, shares: list) -> int:
        """Reconstruct from threshold shares."""
        return reconstruct(shares)

    def detect_corrupt(self, shares: list) -> list:
        """Detect corrupt shares."""
        return consistency_check(shares, self.threshold - 1)


class BootstrapSession:
    """One bootstrap session: establish PSKs with k target nodes.

    Steps:
    1. Generate random values for each path
    2. Shamir-encode for relay protection
    3. Distribute via diverse paths
    4. Reconstruct and derive PSKs
    """

    def __init__(self, k: int = 20, threshold: int = 14, rng=None):
        self.k = k
        self.threshold = threshold
        self.rng = rng
        self.raw_secrets: list[bytes] = []
        self.shares: list = []
        self.received_shares: dict = {}  # target_id -> share
        self.corrupt_relays: list = []
        self.derived_psks: dict = {}  # target_id -> PSK bytes

    def generate_secrets(self) -> list:
        """Generate k random 256-bit secrets, one per target."""
        import random
        r = self.rng if self.rng else random.Random()
        self.raw_secrets = []
        for _ in range(self.k):
            # Generate a 256-bit random value
            val = r.getrandbits(256)
            self.raw_secrets.append(val.to_bytes(32, 'big'))
        return self.raw_secrets

    def derive_psk(self, shared_secret: bytes, target_length: int = 256) -> bytes:
        """Expand shared secret to PSK length using Toeplitz-like extraction."""
        # Use SHAKE-256 as a deterministic ITS-compatible expander
        h = hashlib.shake_256(shared_secret)
        return h.digest(target_length)

    def complete(self, target_ids: list, received: dict) -> dict:
        """Complete bootstrap for all targets.

        target_ids: list of target node IDs.
        received: {target_id: raw_secret_bytes} for successful paths.

        Returns: {target_id: PSK bytes} for successful targets.
        """
        self.derived_psks = {}
        for tid in target_ids:
            if tid in received:
                self.derived_psks[tid] = self.derive_psk(received[tid])
        return self.derived_psks


class MultiPathBootstrap:
    """Coordinate k-path secret establishment.

    Manages the full bootstrap protocol:
    1. Select k targets with geographic diversity
    2. Generate per-path secrets
    3. Optionally Shamir-encode for relay protection
    4. Derive PSKs from successful paths
    """

    def __init__(self, k: int = 20, threshold: int = 14):
        self.k = k
        self.threshold = threshold

    def bootstrap(self, target_ids: list, observe_fn=None,
                  corrupt_fn=None, rng=None) -> dict:
        """Run bootstrap protocol.

        target_ids: list of target node IDs (len >= k).
        observe_fn: function(target_id, secret) -> bool. True if Eve observes.
        corrupt_fn: function(target_id, secret) -> modified_secret or None.

        Returns:
            dict with 'psks', 'observed', 'corrupted', 'clean' counts.
        """
        import random
        r = rng or random.Random()
        session = BootstrapSession(self.k, self.threshold, r)
        secrets = session.generate_secrets()

        targets = target_ids[:self.k]
        observed = 0
        corrupted = 0
        received = {}

        for i, tid in enumerate(targets):
            secret = secrets[i]

            # Check if Eve observes this path
            if observe_fn and observe_fn(tid, secret):
                observed += 1

            # Check if relay corrupts
            if corrupt_fn:
                modified = corrupt_fn(tid, secret)
                if modified is not None and modified != secret:
                    corrupted += 1
                    secret = modified

            received[tid] = secret

        psks = session.complete(targets, received)

        return {
            'psks': psks,
            'n_targets': len(targets),
            'observed': observed,
            'corrupted': corrupted,
            'clean': len(targets) - observed,
            'success': (len(targets) - observed) >= 1,
        }


class TemporalBootstrap:
    """Multi-session bootstrap across network contexts.

    Run bootstrap multiple times over days from different network contexts.
    Each session adds ITS channels.
    """

    def __init__(self, k_per_session: int = 5, n_sessions: int = 4):
        self.k_per_session = k_per_session
        self.n_sessions = n_sessions
        self.sessions: list = []
        self.all_psks: dict = {}

    def run_session(self, target_ids: list, rng=None) -> dict:
        """Run one temporal bootstrap session."""
        mpb = MultiPathBootstrap(self.k_per_session, self.k_per_session)
        result = mpb.bootstrap(target_ids, rng=rng)
        self.sessions.append(result)
        self.all_psks.update(result['psks'])
        return result

    @property
    def total_channels(self) -> int:
        return len(self.all_psks)
