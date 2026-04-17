//! # Liu protocol Link (in-process simulation)
//!
//! Pairs two `Physics` endpoints (Alice and Bob) and drives them through
//! the full protocol pipeline: multi-exchange correlation, raw-bit
//! extraction, Cascade reconciliation, privacy amplification.
//!
//! This is a **simulation** — both endpoints run in the same process. It's
//! not a network implementation; it's the reference used by tests to
//! verify correctness and by integration code to benchmark throughput /
//! bit-agreement rate. The actual network version lives in
//! `liun-channel::liu_proto`.

use crate::endpoint::{Physics, PhysicsConfig};
use crate::privacy_amp::Toeplitz;
use crate::reconciliation::{cascade_reconcile, leakage_bound};

/// Run one full protocol instance between two endpoints. Returns Alice's
/// and Bob's estimate of the sign of the other's reflection coefficient.
///
/// In ITS mode (both configs have `rng_is_true_random=true`), the sender's
/// real last-sent value is passed out-of-band via `incoming_real`.
/// In non-ITS mode, unwrap uses hypothesis tracking.
pub fn run_proto_once(alice: &mut Physics, bob: &mut Physics) -> (bool, bool) {
    alice.reset();
    bob.reset();
    bob.set_second_mover(true);

    let its = alice.config.rng_is_true_random;
    let n = alice.config.number_of_exchanges;

    // Alice's k=0.
    let mut wa = alice.exchange(0.0, None);
    for _ in 0..n {
        let real_a = if its { Some(alice.last_real_sent()) } else { None };
        let wb = bob.exchange(wa, real_a);
        let real_b = if its { Some(bob.last_real_sent()) } else { None };
        wa = alice.exchange(wb, real_b);
    }

    (alice.estimate_other(), bob.estimate_other())
}

/// Run `n_runs` protocol runs, collect raw bits, return the raw agreement
/// rate and the bit vectors.
pub struct RawRunResult {
    pub bits_a: Vec<u8>,
    pub bits_b: Vec<u8>,
    pub raw_agreement_rate: f64,
}

pub fn run_proto_batch(
    alice: &mut Physics,
    bob: &mut Physics,
    n_runs: usize,
) -> RawRunResult {
    let mut bits_a = Vec::with_capacity(n_runs);
    let mut bits_b = Vec::with_capacity(n_runs);
    for _ in 0..n_runs {
        // Independent signs per run (randomized privacy).
        let sign_a: f64 = if crate::noise::batch_gaussian(1)[0] > 0.0 { 1.0 } else { -1.0 };
        let sign_b: f64 = if crate::noise::batch_gaussian(1)[0] > 0.0 { 1.0 } else { -1.0 };
        alice.config.reflection_coefficient = sign_a * alice.config.reflection_coefficient.abs();
        bob.config.reflection_coefficient = sign_b * bob.config.reflection_coefficient.abs();

        let (a_est, b_est) = run_proto_once(alice, bob);
        // Each party's "bit" is its own sign XOR the other's estimated sign.
        // With our convention estimate_other() = (correlation_sum > 0), which
        // correlates with sign of the other's α, the bits are:
        //   alice_bit = (alice's estimate of Bob's sign) XOR (Alice's own sign > 0)
        // If signs agree when alice.α>0 and bob.α>0, both get `true`.
        let alice_bit = a_est ^ (sign_a < 0.0);
        let bob_bit = b_est ^ (sign_b < 0.0);
        bits_a.push(if alice_bit { 1 } else { 0 });
        bits_b.push(if bob_bit { 1 } else { 0 });
    }

    let agreements = bits_a.iter().zip(bits_b.iter()).filter(|(a, b)| a == b).count();
    let rate = agreements as f64 / n_runs as f64;
    RawRunResult { bits_a, bits_b, raw_agreement_rate: rate }
}

/// Full pipeline: batch → reconcile → privacy-amplify.
///
/// Returns `(secure_bits, n_raw, n_secure, leaked_bits)`.
/// `secure_bits` is identical on Alice's and Bob's side after reconciliation.
pub struct PipelineResult {
    pub secure_bits: Vec<u8>,
    pub n_raw: usize,
    pub n_secure: usize,
    pub leaked_bits: usize,
    pub raw_agreement_rate: f64,
}

pub fn run_with_reconciliation_and_pa(
    alice: &mut Physics,
    bob: &mut Physics,
    n_runs: usize,
    eve_info_per_bit: f64,
    safety_margin: usize,
    pa_seed_bytes: &[u8],
    reconciliation_seed: u64,
) -> PipelineResult {
    let raw = run_proto_batch(alice, bob, n_runs);
    let n_raw = raw.bits_a.len();
    if n_raw == 0 {
        return PipelineResult {
            secure_bits: Vec::new(), n_raw: 0, n_secure: 0,
            leaked_bits: 0, raw_agreement_rate: raw.raw_agreement_rate,
        };
    }

    // Reconciliation: correct bits_b to match bits_a.
    let mut bits_b = raw.bits_b.clone();
    let leaked = cascade_reconcile(&raw.bits_a, &mut bits_b, 10, 8, reconciliation_seed);
    assert_eq!(raw.bits_a, bits_b, "reconciliation failed to fully correct");

    // n_secure = n_raw - ceil(eve_info) - leaked - safety_margin
    let eve_info = (eve_info_per_bit * n_raw as f64).ceil() as usize;
    let n_secure = n_raw
        .saturating_sub(eve_info)
        .saturating_sub(leaked)
        .saturating_sub(safety_margin);
    if n_secure == 0 {
        return PipelineResult {
            secure_bits: Vec::new(), n_raw, n_secure: 0,
            leaked_bits: leaked, raw_agreement_rate: raw.raw_agreement_rate,
        };
    }

    let toeplitz = Toeplitz::new(pa_seed_bytes, n_raw, n_secure)
        .expect("toeplitz seed too short");
    let secure = toeplitz.hash(&raw.bits_a);

    PipelineResult {
        secure_bits: secure,
        n_raw, n_secure, leaked_bits: leaked,
        raw_agreement_rate: raw.raw_agreement_rate,
    }
}

/// Default protocol configuration for testing / demos. `sigma/p = 2`, which
/// gives strongly-uniform wire values and a good raw agreement rate.
pub fn default_protocol_config() -> PhysicsConfig {
    let cutoff = 0.1;
    let sigma_z = crate::endpoint::estimate_sigma_z(cutoff);
    PhysicsConfig {
        number_of_exchanges: 200,
        reflection_coefficient: 0.5,
        cutoff,
        ramp_time: 10,
        resolution: 0.0,
        masking_time: 0,
        masking_magnitude: 0.0,
        modulus: 2.0 * sigma_z, // sigma/p = 0.5 → strong uniformity
        ramp_exclusion_factor: 3.0,
        rng_is_true_random: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_run_returns_bools() {
        let mut a = Physics::new(default_protocol_config());
        let mut b = Physics::new(default_protocol_config());
        let (x, y) = run_proto_once(&mut a, &mut b);
        // Should not panic; values are already bools.
        let _ = (x, y);
    }

    #[test]
    fn test_batch_produces_high_agreement() {
        let mut a = Physics::new(default_protocol_config());
        let mut b = Physics::new(default_protocol_config());
        let result = run_proto_batch(&mut a, &mut b, 100);
        assert_eq!(result.bits_a.len(), 100);
        assert_eq!(result.bits_b.len(), 100);
        // Raw agreement should be well above 50% (Liu's noise asymmetry).
        assert!(result.raw_agreement_rate > 0.75,
            "raw agreement {:.2} too low — protocol not working",
            result.raw_agreement_rate);
    }

    #[test]
    fn test_full_pipeline_yields_agreed_secure_bits() {
        let mut a = Physics::new(default_protocol_config());
        let mut b = Physics::new(default_protocol_config());
        let seed = [0xA5u8; 256]; // plenty for Toeplitz
        let result = run_with_reconciliation_and_pa(
            &mut a, &mut b,
            500,        // n_runs
            0.1,        // eve_info_per_bit (placeholder)
            10,         // safety_margin
            &seed,
            0x1234_5678,
        );
        // After reconciliation, secure_bits exists only on one side of the
        // sim; the other side would run the same Toeplitz on its own bits
        // (which now equal bits_a after reconcile). Both sides would match.
        assert!(result.n_secure > 0,
            "expected secure bits after PA (n_raw={}, leaked={})",
            result.n_raw, result.leaked_bits);
        assert_eq!(result.secure_bits.len(), result.n_secure);
    }

    #[test]
    fn test_leakage_bound_consistent() {
        let n = 100;
        let bound = leakage_bound(n, 10, 8);
        // Reasonable range: 1000s of bits at most for n=100.
        assert!(bound > 0 && bound < 10000, "unexpected bound {bound}");
    }
}
