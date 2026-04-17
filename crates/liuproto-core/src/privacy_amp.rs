//! # Privacy Amplification via Toeplitz Hashing
//!
//! Standard technique from QKD / leftover hash lemma (LHL).
//!
//! A Toeplitz matrix over GF(2) defined by `n_raw + n_secure - 1` seed bits
//! gives a 2-universal family of hash functions `GF(2)^{n_raw} → GF(2)^{n_secure}`.
//! By the LHL: if the raw input has min-entropy H from Eve, the output length
//! `n_secure ≤ H - 2·log(1/ε)` is ε-close to uniform from Eve's view.
//!
//! Here we use it to turn Liu-protocol raw sign bits (which have positive but
//! <1 bits/bit of min-entropy from Eve's view) into a shorter, genuinely-ITS
//! key stream. The Toeplitz seed does **not** need to be secret (2-universality
//! is the property of the family, not of a particular key), so we derive it
//! deterministically from the session PSK. Both peers derive the same seed.
//!
//! Complexity: hash is O(n_raw · n_secure) bitops. For n_raw=500, n_secure=250
//! that's ~125k ops/round — microseconds per round at chat timescales.
//!
//! Proved in Lean: the Toeplitz construction is 2-universal (see `QKD.lean`
//! in the Liun proofs) and LHL extracts ITS-close-to-uniform output.

use std::fmt;

/// A Toeplitz universal hash `GF(2)^{n_raw} → GF(2)^{n_secure}`.
#[derive(Clone)]
pub struct Toeplitz {
    n_raw: usize,
    n_secure: usize,
    /// Defining sequence of length `n_raw + n_secure - 1`, one bit per element (0 or 1).
    seq: Vec<u8>,
}

impl Toeplitz {
    /// Construct a Toeplitz hash from a seed byte buffer.
    ///
    /// The first `n_raw + n_secure - 1` bits of `seed` (MSB-first within each byte)
    /// become the Toeplitz defining sequence.
    ///
    /// Returns an error if the seed is too short or the dimensions are invalid.
    pub fn new(seed: &[u8], n_raw: usize, n_secure: usize) -> Result<Self, ToeplitzError> {
        if n_secure == 0 || n_raw == 0 {
            return Err(ToeplitzError::ZeroDimension);
        }
        if n_secure > n_raw {
            return Err(ToeplitzError::SecureExceedsRaw { n_secure, n_raw });
        }
        let needed_bits = n_raw + n_secure - 1;
        let have_bits = seed.len() * 8;
        if have_bits < needed_bits {
            return Err(ToeplitzError::SeedTooShort { need: needed_bits, got: have_bits });
        }

        let mut seq = Vec::with_capacity(needed_bits);
        for i in 0..needed_bits {
            let byte = seed[i / 8];
            let bit = (byte >> (7 - (i % 8))) & 1;
            seq.push(bit);
        }
        Ok(Self { n_raw, n_secure, seq })
    }

    /// Number of raw input bits expected.
    pub fn n_raw(&self) -> usize { self.n_raw }

    /// Number of secure output bits produced.
    pub fn n_secure(&self) -> usize { self.n_secure }

    /// Apply the hash. `raw` must be `n_raw` bits (each element 0 or 1).
    /// Returns `n_secure` bits.
    pub fn hash(&self, raw: &[u8]) -> Vec<u8> {
        assert_eq!(raw.len(), self.n_raw,
            "Toeplitz::hash: expected {} raw bits, got {}", self.n_raw, raw.len());

        let mut out = Vec::with_capacity(self.n_secure);
        // Row i (output bit i) uses seq[n_secure-1-i .. n_secure-1-i + n_raw].
        // Compute GF(2) inner product = XOR of (seq[k] AND raw[j]).
        for i in 0..self.n_secure {
            let row_start = self.n_secure - 1 - i;
            let mut bit = 0u8;
            for j in 0..self.n_raw {
                bit ^= (self.seq[row_start + j] & 1) & (raw[j] & 1);
            }
            out.push(bit);
        }
        out
    }
}

/// Errors from building a Toeplitz hash.
#[derive(Debug, PartialEq, Eq)]
pub enum ToeplitzError {
    ZeroDimension,
    SecureExceedsRaw { n_secure: usize, n_raw: usize },
    SeedTooShort { need: usize, got: usize },
}

impl fmt::Display for ToeplitzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDimension => write!(f, "Toeplitz dimensions must be non-zero"),
            Self::SecureExceedsRaw { n_secure, n_raw } =>
                write!(f, "n_secure ({n_secure}) must not exceed n_raw ({n_raw})"),
            Self::SeedTooShort { need, got } =>
                write!(f, "Toeplitz seed too short: need {need} bits, have {got}"),
        }
    }
}

impl std::error::Error for ToeplitzError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dimensions_enforced() {
        let seed = vec![0u8; 100];
        assert!(matches!(Toeplitz::new(&seed, 0, 10), Err(ToeplitzError::ZeroDimension)));
        assert!(matches!(Toeplitz::new(&seed, 10, 20), Err(ToeplitzError::SecureExceedsRaw { .. })));
        assert!(matches!(Toeplitz::new(&[0u8; 1], 100, 50), Err(ToeplitzError::SeedTooShort { .. })));
    }

    #[test]
    fn test_deterministic() {
        // Same seed → same output.
        let seed = vec![0xA5u8; 32];
        let t1 = Toeplitz::new(&seed, 100, 50).unwrap();
        let t2 = Toeplitz::new(&seed, 100, 50).unwrap();
        let raw: Vec<u8> = (0..100).map(|i| (i % 2) as u8).collect();
        assert_eq!(t1.hash(&raw), t2.hash(&raw));
    }

    #[test]
    fn test_output_length() {
        let seed = vec![0xFFu8; 200];
        let t = Toeplitz::new(&seed, 500, 250).unwrap();
        let raw: Vec<u8> = (0..500).map(|i| (i % 2) as u8).collect();
        let out = t.hash(&raw);
        assert_eq!(out.len(), 250);
        for &b in &out {
            assert!(b == 0 || b == 1);
        }
    }

    #[test]
    fn test_linearity() {
        // h is GF(2)-linear: h(x ⊕ y) = h(x) ⊕ h(y).
        let seed = vec![0x5Au8; 128];
        let t = Toeplitz::new(&seed, 64, 32).unwrap();
        let x: Vec<u8> = (0..64).map(|i| (i % 2) as u8).collect();
        let y: Vec<u8> = (0..64).map(|i| ((i / 3) % 2) as u8).collect();
        let xor: Vec<u8> = x.iter().zip(&y).map(|(&a, &b)| a ^ b).collect();
        let hx = t.hash(&x);
        let hy = t.hash(&y);
        let hxor = t.hash(&xor);
        let expected: Vec<u8> = hx.iter().zip(&hy).map(|(&a, &b)| a ^ b).collect();
        assert_eq!(hxor, expected, "Toeplitz hash must be GF(2)-linear");
    }

    #[test]
    fn test_nontrivial() {
        // With a non-zero seed and non-zero input, output should not be all zeros
        // (very unlikely unless seed is degenerate).
        let mut seed = vec![0u8; 200];
        for (i, b) in seed.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(17).wrapping_add(13); }
        let t = Toeplitz::new(&seed, 500, 250).unwrap();
        let raw: Vec<u8> = (0..500).map(|i| ((i * 7 + 3) % 2) as u8).collect();
        let out = t.hash(&raw);
        assert!(out.iter().any(|&b| b == 1), "hash output should not be all zeros");
    }

    #[test]
    fn test_2_universality_spot_check() {
        // Property: for fixed random seed, Pr[h(x) == h(y)] for random distinct x, y
        // should be close to 2^(-n_secure). We don't verify the probability directly
        // (would need thousands of samples) — just verify that two random distinct
        // inputs typically produce different outputs.
        let seed: Vec<u8> = (0..200).map(|i| ((i * 31 + 7) as u8)).collect();
        let t = Toeplitz::new(&seed, 100, 20).unwrap();
        let x: Vec<u8> = (0..100).map(|i| (i % 2) as u8).collect();
        let mut y = x.clone();
        y[0] ^= 1; // flip one bit
        assert_ne!(t.hash(&x), t.hash(&y),
            "single-bit input difference should produce output difference (holds with prob 1 for column 0 nonzero)");
    }
}
