//! # Wegman-Carter Polynomial MAC over GF(M61)
//!
//! Computes tag = s + Σ c_i · r^i (mod M61) via Horner's method.
//! One-time key (r, s) per message. Forgery probability ≤ d/M61
//! where d = number of coefficients.
//!
//! ITS property: Schwartz-Zippel (proved in Lean: SchwartzZippel.lean).
//! The polynomial difference of two messages has ≤ d roots over GF(M61),
//! so a random r hits a root with probability ≤ d/M61 ≈ 5×10⁻¹⁴.

use crate::gf61::Gf61;

/// Compute the Wegman-Carter MAC tag via Horner's method.
///
/// tag = s + c[0]·r^(n-1) + c[1]·r^(n-2) + ... + c[n-1]
///     = s + (((...((c[0]·r + c[1])·r + c[2])·r + ...)·r + c[n-1])
///
/// This is the exact same computation as the C extension and the
/// Python implementation, proved correct in Lean (WegmanCarter.lean).
///
/// For inputs larger than 64 coefficients this auto-dispatches to a
/// 4-way parallel Horner variant (see `mac_tag_parallel4`) that breaks
/// the serial multiply-chain dependency. Output is bit-identical.
#[inline]
pub fn mac_tag(coeffs: &[Gf61], r: Gf61, s: Gf61) -> Gf61 {
    if coeffs.len() >= 64 {
        mac_tag_parallel4(coeffs, r, s)
    } else {
        mac_tag_scalar(coeffs, r, s)
    }
}

/// Scalar Horner implementation — retained as the reference and as
/// the fast path for short inputs where the parallel setup cost
/// would dominate.
#[inline]
pub fn mac_tag_scalar(coeffs: &[Gf61], r: Gf61, s: Gf61) -> Gf61 {
    let mut h = Gf61::ZERO;
    for &c in coeffs {
        h = h * r + c;
    }
    h + s
}

/// 4-way parallel Horner.
///
/// The scalar Horner recurrence `h_{i+1} = h_i * r + c_{i+1}` has a
/// serial multiply-chain dependency: on modern OOO cores a 64×64→128
/// MULQ is ~5 cycles latency but 1/cycle throughput, so the scalar
/// loop is latency-bound at ~5 cycles per coefficient.
///
/// Splitting the polynomial into 4 interleaved sub-streams, each
/// advanced with multiplier `r^4`, produces 4 independent Horner
/// chains that the CPU can overlap. After processing all complete
/// blocks of 4 coefficients we combine via
///   `H = r^3·h_0 + r^2·h_1 + r·h_2 + h_3`
/// which is algebraically the same polynomial. Remaining
/// coefficients (up to 3) are folded scalar-wise.
///
/// Correctness derivation: the scalar polynomial over 4B coefficients
/// is `Σ_{b=0..B-1} Σ_{j=0..3} c[4b+j] · r^{4B-1-4b-j}`. Grouping by
/// residue j gives `Σ_j r^{3-j} · Σ_b c[4b+j] · r^{4(B-1-b)}`; each
/// inner sum is exactly `h_j`.
#[inline]
pub fn mac_tag_parallel4(coeffs: &[Gf61], r: Gf61, s: Gf61) -> Gf61 {
    let n = coeffs.len();
    if n < 4 {
        return mac_tag_scalar(coeffs, r, s);
    }

    // Precompute r^2, r^3, r^4.
    let r2 = r * r;
    let r3 = r2 * r;
    let r4 = r2 * r2;

    let mut h0 = Gf61::ZERO;
    let mut h1 = Gf61::ZERO;
    let mut h2 = Gf61::ZERO;
    let mut h3 = Gf61::ZERO;

    let full_blocks = n / 4;
    let mut i = 0;
    for _ in 0..full_blocks {
        h0 = h0 * r4 + coeffs[i];
        h1 = h1 * r4 + coeffs[i + 1];
        h2 = h2 * r4 + coeffs[i + 2];
        h3 = h3 * r4 + coeffs[i + 3];
        i += 4;
    }

    // Combine the 4 lanes.
    let mut h = h0 * r3 + h1 * r2 + h2 * r + h3;

    // Fold any tail (0..3 leftover coefficients) scalar-wise.
    while i < n {
        h = h * r + coeffs[i];
        i += 1;
    }

    h + s
}

/// Verify a MAC tag in constant time. Returns true if the tag matches.
///
/// Uses `subtle::ConstantTimeEq` on the underlying u64 so the comparison
/// itself does not branch on tag equality. (The caller still branches on
/// the final bool; the leaked information is at most "match or mismatch",
/// never which byte/bit differed.)
#[inline]
pub fn mac_verify(coeffs: &[Gf61], r: Gf61, s: Gf61, tag: Gf61) -> bool {
    use subtle::ConstantTimeEq;
    let computed = mac_tag(coeffs, r, s);
    computed.val().ct_eq(&tag.val()).into()
}

/// Constant-time tag equality helper. Equivalent to `a == b` but does not
/// leak timing information about which bits differ.
#[inline]
pub fn tags_ct_eq(a: Gf61, b: Gf61) -> bool {
    use subtle::ConstantTimeEq;
    a.val().ct_eq(&b.val()).into()
}

/// Derive MAC key (r, s) from PSK bytes XOR'd with nonce.
/// Uses first 8 bytes for r, next 8 for s.
pub fn derive_mac_key(psk: &[u8], nonce: &[u8; 16]) -> (Gf61, Gf61) {
    assert!(psk.len() >= 16, "PSK too short for MAC key derivation");
    let mut r_bytes = [0u8; 8];
    let mut s_bytes = [0u8; 8];
    for i in 0..8 {
        r_bytes[i] = psk[i] ^ nonce[i];
        s_bytes[i] = psk[i + 8] ^ nonce[i + 8];
    }
    (Gf61::random(&r_bytes), Gf61::random(&s_bytes))
}

/// Quantize wire values into MAC coefficients.
/// Maps continuous values to bin indices and packs into field elements.
pub fn quantize_to_coeffs(values: &[f64], sigma_z: f64, n_bits: u32, range_sigma: f64) -> Vec<Gf61> {
    let r = range_sigma * sigma_z;
    let n_bins = 1u64 << n_bits;
    let delta = 2.0 * r / n_bins as f64;
    let bins_per_pack = 61 / n_bits;

    let mut bins: Vec<u64> = values.iter().map(|&v| {
        let clipped = v.max(-r).min(r - 1e-15);
        let idx = ((clipped + r) / delta) as u64;
        idx.min(n_bins - 1)
    }).collect();

    // Pad to multiple of bins_per_pack
    let pad = (bins_per_pack as usize - bins.len() % bins_per_pack as usize) % bins_per_pack as usize;
    bins.extend(std::iter::repeat(0).take(pad));

    // Pack bins into field elements
    let base = n_bins;
    bins.chunks(bins_per_pack as usize)
        .map(|group| {
            let mut packed = 0u64;
            for &b in group {
                packed = packed * base + b;
            }
            Gf61::new(packed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_empty() {
        let s = Gf61::new(42);
        assert_eq!(mac_tag(&[], Gf61::new(7), s), s);
    }

    #[test]
    fn test_mac_single() {
        // tag = s + c[0] = 42 + 10 = 52
        let c = [Gf61::new(10)];
        assert_eq!(mac_tag(&c, Gf61::new(7), Gf61::new(42)).val(), 52);
    }

    #[test]
    fn test_mac_horner() {
        // coeffs = [1, 1], r = M61-1 (= -1), s = 0
        // tag = ((0·(-1) + 1)·(-1) + 1) = (-1 + 1) = 0
        let c = [Gf61::new(1), Gf61::new(1)];
        let tag = mac_tag(&c, Gf61::new(crate::gf61::M61 - 1), Gf61::ZERO);
        assert_eq!(tag.val(), 0);
    }

    #[test]
    fn test_mac_verify() {
        let c = [Gf61::new(3), Gf61::new(5), Gf61::new(7)];
        let r = Gf61::new(11);
        let s = Gf61::new(13);
        let tag = mac_tag(&c, r, s);
        assert!(mac_verify(&c, r, s, tag));
        assert!(!mac_verify(&c, r, s, tag + Gf61::ONE));
    }

    #[test]
    fn test_quantize() {
        let values = vec![0.0, 0.5, -0.5, 1.0];
        let coeffs = quantize_to_coeffs(&values, 1.0, 4, 4.0);
        assert!(!coeffs.is_empty());
        // Each coefficient should be a valid field element
        for c in &coeffs {
            assert!(c.val() < crate::gf61::M61);
        }
    }

    /// `mac_tag_parallel4` must agree with `mac_tag_scalar` bit-for-bit
    /// for every input length. This covers each remainder class
    /// (n mod 4 ∈ {0,1,2,3}) plus the auto-dispatch boundary at 64.
    #[test]
    fn parallel4_matches_scalar_over_lengths() {
        let r = Gf61::new(0x1234_5678_9ABC_DEF0);
        let s = Gf61::new(0xDEAD_BEEF_CAFE_BABE);
        // Deterministic pseudo-random coefficient sequence.
        let mut coeffs: Vec<Gf61> = Vec::with_capacity(300);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..300 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            coeffs.push(Gf61::new(x));
        }
        for n in [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 65, 128, 129, 300] {
            let scalar = mac_tag_scalar(&coeffs[..n], r, s);
            let parallel = mac_tag_parallel4(&coeffs[..n], r, s);
            assert_eq!(
                scalar, parallel,
                "n={n}: parallel {parallel:?} vs scalar {scalar:?}"
            );
            // The public `mac_tag` also routes here; ensure parity.
            assert_eq!(mac_tag(&coeffs[..n], r, s), scalar);
        }
    }

    /// Algebraic identity: `mac(c, r, s) = s + Σ c_i · r^i`. Spot-check
    /// with the scalar by expanding by hand for tiny n, then against
    /// scalar for larger n.
    #[test]
    fn parallel4_horner_identity() {
        // Manual formula for n=5: s + c0·r^4 + c1·r^3 + c2·r^2 + c3·r + c4.
        let r = Gf61::new(7);
        let s = Gf61::new(11);
        let c: Vec<Gf61> = [3u64, 5, 2, 9, 4].iter().map(|&v| Gf61::new(v)).collect();
        let r2 = r * r;
        let r3 = r2 * r;
        let r4 = r2 * r2;
        let expected = s + c[0] * r4 + c[1] * r3 + c[2] * r2 + c[3] * r + c[4];
        assert_eq!(mac_tag_parallel4(&c, r, s), expected);
    }
}
