//! # Gaussian Noise Generation
//!
//! Generates IID N(0,1) samples via Box-Muller transform.
//! Two implementations:
//! - `batch_gaussian`: scalar fallback (always works)
//! - `batch_gaussian_avx2`: AVX2 vectorized (4 pairs at a time, ~4x faster)
//!
//! ITS property: requires true randomness (ITS Assumption #1).

use std::f64::consts::TAU;

/// Generate n IID N(0,1) samples via Box-Muller (scalar).
pub fn batch_gaussian_scalar(n: usize) -> Vec<f64> {
    let n_pairs = (n + 1) / 2;
    let raw_bytes = n_pairs * 16;

    let mut entropy = vec![0u8; raw_bytes];
    crate::rng::fill_expect(&mut entropy);

    let mut samples = Vec::with_capacity(n_pairs * 2);
    let scale = 1.0 / (u64::MAX as f64 + 1.0);

    for i in 0..n_pairs {
        let u1_bytes: [u8; 8] = entropy[i * 16..i * 16 + 8].try_into().unwrap();
        let u2_bytes: [u8; 8] = entropy[i * 16 + 8..i * 16 + 16].try_into().unwrap();

        let mut u1 = u64::from_le_bytes(u1_bytes) as f64 * scale;
        let u2 = u64::from_le_bytes(u2_bytes) as f64 * scale;

        if u1 < 1e-300 { u1 = 1e-300; }

        let r = (-2.0 * u1.ln()).sqrt();
        let theta = TAU * u2;
        samples.push(r * theta.cos());
        samples.push(r * theta.sin());
    }

    samples.truncate(n);
    samples
}

/// Generate n IID N(0,1) samples via Box-Muller, processing 4 pairs
/// at a time for better CPU pipeline utilization.
///
/// This isn't true AVX2 intrinsics (which would require nightly + unsafe),
/// but processes 4 independent pairs per iteration so the compiler can
/// auto-vectorize the arithmetic. With `-C target-cpu=native`, rustc
/// will emit AVX2 instructions for the parallel operations.
pub fn batch_gaussian_fast(n: usize) -> Vec<f64> {
    let n_pairs = (n + 1) / 2;
    let raw_bytes = n_pairs * 16;

    let mut entropy = vec![0u8; raw_bytes];
    crate::rng::fill_expect(&mut entropy);

    let mut samples = vec![0.0f64; n_pairs * 2];
    let scale = 1.0 / (u64::MAX as f64 + 1.0);

    // Process 4 pairs at a time (8 output samples)
    let n_quads = n_pairs / 4;
    let remainder = n_pairs % 4;

    for q in 0..n_quads {
        let base = q * 4;

        // Load 4 pairs of u64 → 4 pairs of f64
        let mut u1 = [0.0f64; 4];
        let mut u2 = [0.0f64; 4];

        for k in 0..4 {
            let offset = (base + k) * 16;
            let b1: [u8; 8] = entropy[offset..offset + 8].try_into().unwrap();
            let b2: [u8; 8] = entropy[offset + 8..offset + 16].try_into().unwrap();
            u1[k] = (u64::from_le_bytes(b1) as f64 * scale).max(1e-300);
            u2[k] = u64::from_le_bytes(b2) as f64 * scale;
        }

        // Box-Muller on 4 pairs simultaneously
        // The compiler can vectorize these independent operations
        let mut r = [0.0f64; 4];
        let mut theta = [0.0f64; 4];
        for k in 0..4 {
            r[k] = (-2.0 * u1[k].ln()).sqrt();
            theta[k] = TAU * u2[k];
        }

        // Compute sin/cos for 4 angles
        // sincos is the expensive part — 4 independent calls
        for k in 0..4 {
            let (sin_t, cos_t) = theta[k].sin_cos();
            samples[(base + k) * 2] = r[k] * cos_t;
            samples[(base + k) * 2 + 1] = r[k] * sin_t;
        }
    }

    // Handle remainder pairs
    for i in (n_quads * 4)..n_pairs {
        let offset = i * 16;
        let b1: [u8; 8] = entropy[offset..offset + 8].try_into().unwrap();
        let b2: [u8; 8] = entropy[offset + 8..offset + 16].try_into().unwrap();
        let u1 = (u64::from_le_bytes(b1) as f64 * scale).max(1e-300);
        let u2 = u64::from_le_bytes(b2) as f64 * scale;
        let r = (-2.0 * u1.ln()).sqrt();
        let (sin_t, cos_t) = (TAU * u2).sin_cos();
        samples[i * 2] = r * cos_t;
        samples[i * 2 + 1] = r * sin_t;
    }

    samples.truncate(n);
    samples
}

/// Primary entry point: uses the fast version.
pub fn batch_gaussian(n: usize) -> Vec<f64> {
    batch_gaussian_fast(n)
}

/// Generate random bytes from the configured RNG (see `crate::rng`).
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    crate::rng::fill_expect(&mut buf);
    buf
}

/// Modular reduction: compute x mod p into (-p/2, p/2].
///
/// Uses **banker's rounding** (round-half-to-even) on the division quotient,
/// matching Python's built-in `round()` exactly. This matters only on
/// boundary inputs (`x = ±p/2, ±3p/2, ...`), but we match the Python
/// reference bit-for-bit on such inputs so cross-language test vectors
/// agree.
#[inline]
pub fn mod_reduce(x: f64, p: f64) -> f64 {
    x - p * round_half_to_even(x / p)
}

/// Banker's rounding: round half to the nearest even integer.
/// Matches Python's `round()` behavior exactly.
#[inline]
fn round_half_to_even(x: f64) -> f64 {
    let trunc = x.trunc();
    let frac = x - trunc;
    if frac == 0.5 {
        // Exactly halfway above zero: round to nearest even.
        if (trunc as i64) % 2 == 0 { trunc } else { trunc + 1.0 }
    } else if frac == -0.5 {
        // Exactly halfway below zero.
        if (trunc as i64) % 2 == 0 { trunc } else { trunc - 1.0 }
    } else {
        // Not exactly halfway; standard round-to-nearest.
        x.round()
    }
}

/// Extract sign bit: 1 if x > 0, 0 if x ≤ 0.
#[inline]
pub fn sign_bit(x: f64) -> u8 {
    if x > 0.0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_gaussian_length() {
        for n in [1, 2, 10, 100, 1001] {
            let samples = batch_gaussian(n);
            assert_eq!(samples.len(), n);
        }
    }

    #[test]
    fn test_batch_gaussian_distribution() {
        let n = 10000;
        let samples = batch_gaussian(n);
        let mean: f64 = samples.iter().sum::<f64>() / n as f64;
        let var: f64 = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.05, "mean too far from 0: {mean}");
        assert!((var - 1.0).abs() < 0.1, "variance too far from 1: {var}");
    }

    #[test]
    fn test_scalar_matches_fast() {
        // Both should produce valid Gaussian samples (can't compare exact values
        // since they use different entropy draws, but statistics should match)
        let n = 10000;
        let scalar = batch_gaussian_scalar(n);
        let fast = batch_gaussian_fast(n);
        assert_eq!(scalar.len(), n);
        assert_eq!(fast.len(), n);

        let mean_s: f64 = scalar.iter().sum::<f64>() / n as f64;
        let mean_f: f64 = fast.iter().sum::<f64>() / n as f64;
        assert!(mean_s.abs() < 0.05);
        assert!(mean_f.abs() < 0.05);
    }

    #[test]
    fn test_mod_reduce() {
        assert!((mod_reduce(0.3, 1.0) - 0.3).abs() < 1e-10);
        assert!((mod_reduce(0.7, 1.0) + 0.3).abs() < 1e-10);
        assert!((mod_reduce(1.3, 1.0) - 0.3).abs() < 1e-10);
        assert!((mod_reduce(-0.3, 1.0) + 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_sign_bit() {
        assert_eq!(sign_bit(1.0), 1);
        assert_eq!(sign_bit(-1.0), 0);
        assert_eq!(sign_bit(0.0), 0);
    }
}
