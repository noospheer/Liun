"""Real Liu protocol channel adapter using liuproto.StreamPipe.

Wraps StreamPipe (in-process Gaussian noise exchange + privacy amplification)
to provide the same interface as MockLiuChannel. Key material is generated
by real physics (not mocked), closing the gap between simulation and production.

Both endpoints of the same channel share a single StreamPipe via a class-level
registry keyed by channel_id. Alice reads from key_buffer_alice, Bob from
key_buffer_bob; both buffers contain identical bytes (shared accumulator).
"""

from liuproto import StreamPipe
from liuproto.link import _its_mac_tag_tree, _psk_mac_keys


class RealLiuChannel:
    """Real Liu protocol channel using liuproto.StreamPipe.

    Provides the same interface as MockLiuChannel but generates key material
    via actual Gaussian noise exchange and Toeplitz hashing.
    """

    # Shared pipe registry: channel_id -> StreamPipe.
    # Both endpoints of the same channel share one pipe so that
    # key material agrees (identical bytes in both buffers).
    _pipes = {}

    def __init__(self, node_a: int, node_b: int, psk: bytes,
                 throughput_bps: int = 2_000_000,
                 chunk_steps: int = 1001, n_bits: int = 8):
        self.node_a = node_a
        self.node_b = node_b
        self.psk = psk
        self.throughput_bps = throughput_bps
        self.run_idx = 0
        self.total_bits_generated = 0
        self.active = True

        cid = (min(node_a, node_b), max(node_a, node_b))
        self._role = 'alice' if node_a < node_b else 'bob'

        if cid not in RealLiuChannel._pipes:
            pipe = StreamPipe(
                cutoff=0.1, ramp_time=20, chunk_steps=chunk_steps,
                n_bits=n_bits, target_epsilon=1e-6)
            pipe.run()  # run until first chunk completes
            RealLiuChannel._pipes[cid] = pipe

        self._pipe = RealLiuChannel._pipes[cid]
        self._key_buf = (self._pipe.key_buffer_alice if self._role == 'alice'
                         else self._pipe.key_buffer_bob)

    @property
    def channel_id(self) -> tuple:
        return (min(self.node_a, self.node_b), max(self.node_a, self.node_b))

    def generate_key_bits(self, n_bits: int) -> bytes:
        """Generate n_bits of ITS key material from real physics.

        Returns ceil(n_bits/8) bytes.
        """
        if not self.active:
            raise RuntimeError("Channel is not active")
        n_bytes = (n_bits + 7) // 8
        # Run more exchanges if buffer is insufficient
        while self._key_buf.available < n_bytes:
            self._pipe.run()
        result = self._key_buf.get(n_bytes, block=False)
        self.total_bits_generated += n_bits
        return result

    def authenticate(self, data: list, run_idx: int = None) -> int:
        """Compute MAC tag on data using PSK-derived keys.

        Uses liuproto's vectorized tree-reduction Wegman-Carter MAC.
        """
        if run_idx is None:
            run_idx = self.run_idx
        r, s = _psk_mac_keys(self.psk, run_idx)
        return _its_mac_tag_tree(data, r, s)

    def verify_mac(self, data: list, tag: int, run_idx: int = None) -> bool:
        """Verify a MAC tag."""
        return self.authenticate(data, run_idx) == tag

    def advance_run(self):
        """Move to next run (new MAC keys)."""
        self.run_idx += 1

    def close(self):
        """Mark channel as inactive."""
        self.active = False

    @classmethod
    def reset(cls):
        """Clear the shared pipe registry. Call between tests."""
        cls._pipes.clear()
