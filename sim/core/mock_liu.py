"""Mock Liu channel: random key bytes on demand, real GF(M61) MAC.

The Liu protocol has 166 tests. We don't re-test Gaussian noise exchange.
We DO test the polynomial MAC because it's the same GF(M61) primitive
shared across Shamir, USS, and Liu.
"""

import os
import struct
from liun.gf61 import M61, poly_eval, rand_element


def _psk_extract_mac_keys(psk: bytes, run_idx: int) -> tuple:
    """Extract (r, s) MAC keys from PSK for a given run index.

    Mirrors Liup's _psk_mac_keys layout:
    bytes [32 + run_idx*18 + 2 .. +17] -> (r, s)
    """
    off = 32 + run_idx * 18 + 2
    if off + 16 > len(psk):
        raise ValueError(f"PSK too short for run_idx={run_idx}")
    r = int.from_bytes(psk[off:off + 8], 'big') % M61
    s = int.from_bytes(psk[off + 8:off + 16], 'big') % M61
    return r, s


def mac_tag(coeffs: list, r: int, s: int) -> int:
    """Wegman-Carter MAC: polynomial eval at r, OTP with s, mod M61.

    Same as Liup's _its_mac_tag. Real GF(M61) computation.
    coeffs: [c_n-1, c_n-2, ..., c_1, c_0] (highest degree first).
    tag = (poly(r) + s) mod M61
    """
    h = poly_eval(coeffs, r)
    return (h + s) % M61


class MockLiuChannel:
    """Simulates a Liu ITS channel between two nodes.

    Provides:
    - Random key bytes on demand (simulates Liu key generation)
    - Real GF(M61) MAC computation (same math as Liup)
    - PSK lifecycle tracking
    """

    def __init__(self, node_a: int, node_b: int, psk: bytes,
                 throughput_bps: int = 2_000_000):
        self.node_a = node_a
        self.node_b = node_b
        self.psk = psk
        self.throughput_bps = throughput_bps
        self.run_idx = 0
        self.total_bits_generated = 0
        self.active = True
        self._rng_state = int.from_bytes(psk[:32], 'big')

    @property
    def channel_id(self) -> tuple:
        return (min(self.node_a, self.node_b), max(self.node_a, self.node_b))

    def generate_key_bits(self, n_bits: int) -> bytes:
        """Generate n_bits of ITS key material (simulated).

        Returns ceil(n_bits/8) bytes.
        """
        if not self.active:
            raise RuntimeError("Channel is not active")
        n_bytes = (n_bits + 7) // 8
        # Deterministic: hash state forward
        import hashlib
        result = b''
        while len(result) < n_bytes:
            self._rng_state += 1
            h = hashlib.sha256(self._rng_state.to_bytes(32, 'big'))
            result += h.digest()
        self.total_bits_generated += n_bits
        return result[:n_bytes]

    def authenticate(self, data: list, run_idx: int = None) -> int:
        """Compute MAC tag on data using PSK-derived keys.

        data: list of int coefficients (highest degree first).
        Returns: MAC tag (int).
        """
        if run_idx is None:
            run_idx = self.run_idx
        r, s = _psk_extract_mac_keys(self.psk, run_idx)
        return mac_tag(data, r, s)

    def verify_mac(self, data: list, tag: int, run_idx: int = None) -> bool:
        """Verify a MAC tag."""
        return self.authenticate(data, run_idx) == tag

    def advance_run(self):
        """Move to next run (new MAC keys)."""
        self.run_idx += 1

    def close(self):
        self.active = False


def create_channel(node_a, node_b, psk, use_real=False, **kwargs):
    """Factory: create MockLiuChannel or RealLiuChannel."""
    if use_real:
        from sim.core.liu_adapter import RealLiuChannel
        return RealLiuChannel(node_a, node_b, psk, **kwargs)
    return MockLiuChannel(node_a, node_b, psk, **kwargs)
