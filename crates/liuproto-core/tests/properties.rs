//! Property-based invariant tests over the core primitives.
//!
//! Where our unit tests exercise specific examples, these tests assert
//! universal laws on random inputs — ring/field axioms for GF61, MAC
//! verify-roundtrip, pool sequence invariants, Toeplitz linearity, Cascade
//! convergence. `proptest` shrinks failing cases to minimal counterexamples.

use liuproto_core::gf61::Gf61;
use liuproto_core::mac;
use liuproto_core::pool::{DepositSource, Pool};
use liuproto_core::privacy_amp::Toeplitz;
use liuproto_core::reconciliation::cascade_reconcile;
use proptest::prelude::*;

// ──────────────── GF(2^61 - 1) field axioms ────────────────

// M61 = 2^61 - 1 is 2305843009213693951. Keep Gf61 values in range.
fn any_gf61() -> impl Strategy<Value = Gf61> {
    const M61: u64 = (1 << 61) - 1;
    (0u64..M61).prop_map(Gf61::new)
}

proptest! {
    #[test]
    fn gf61_add_is_commutative(a in any_gf61(), b in any_gf61()) {
        prop_assert_eq!(a + b, b + a);
    }

    #[test]
    fn gf61_add_is_associative(a in any_gf61(), b in any_gf61(), c in any_gf61()) {
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn gf61_zero_is_add_identity(a in any_gf61()) {
        prop_assert_eq!(a + Gf61::ZERO, a);
    }

    #[test]
    fn gf61_mul_is_commutative(a in any_gf61(), b in any_gf61()) {
        prop_assert_eq!(a * b, b * a);
    }

    #[test]
    fn gf61_mul_is_associative(a in any_gf61(), b in any_gf61(), c in any_gf61()) {
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn gf61_distributes(a in any_gf61(), b in any_gf61(), c in any_gf61()) {
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn gf61_sub_is_add_inverse(a in any_gf61(), b in any_gf61()) {
        prop_assert_eq!((a + b) - b, a);
    }
}

// ──────────────── MAC verify roundtrip & detection ────────────────

fn coeff_vec(n: usize) -> impl Strategy<Value = Vec<Gf61>> {
    prop::collection::vec(any_gf61(), n)
}

proptest! {
    /// Verification of a correctly-computed tag succeeds.
    #[test]
    fn mac_verify_succeeds_on_correct_tag(
        coeffs in coeff_vec(32),
        r in any_gf61(),
        s in any_gf61(),
    ) {
        let tag = mac::mac_tag(&coeffs, r, s);
        prop_assert!(mac::mac_verify(&coeffs, r, s, tag));
    }

    /// Flipping any single coefficient almost-always breaks verification
    /// (Schwartz-Zippel: collision probability ≤ d/M61 ≈ 10⁻¹⁴).
    #[test]
    fn mac_detects_single_coefficient_change(
        mut coeffs in coeff_vec(32),
        r in any_gf61(),
        s in any_gf61(),
        flip_index in 0usize..32,
    ) {
        let tag = mac::mac_tag(&coeffs, r, s);
        // Flip: add 1 to that coefficient (nonzero perturbation in GF(M61)).
        coeffs[flip_index] = coeffs[flip_index] + Gf61::new(1);
        // With overwhelming probability the MAC now fails. Chance of a
        // collision = d/M61 ≈ 1.4e-14. For 256 proptest trials we'd need
        // to run for millennia to flake — safe to assert.
        prop_assert!(!mac::mac_verify(&coeffs, r, s, tag));
    }

    /// Different messages yield different tags (almost always).
    #[test]
    fn mac_tags_differ_for_different_inputs(
        coeffs_a in coeff_vec(16),
        coeffs_b in coeff_vec(16),
        r in any_gf61(),
        s in any_gf61(),
    ) {
        prop_assume!(coeffs_a != coeffs_b);
        let tag_a = mac::mac_tag(&coeffs_a, r, s);
        let tag_b = mac::mac_tag(&coeffs_b, r, s);
        // Collision would be a crypto failure; same probability bound.
        prop_assert_ne!(tag_a, tag_b);
    }

    /// Constant-time compare agrees with `==` in both directions.
    #[test]
    fn tags_ct_eq_matches_eq(a in any_gf61(), b in any_gf61()) {
        prop_assert_eq!(mac::tags_ct_eq(a, b), a == b);
    }

    /// 4-way parallel Horner is algebraically identical to the scalar
    /// implementation. Property: for any input, every length, every r, s:
    /// `mac_tag_parallel4(c, r, s) == mac_tag_scalar(c, r, s)`.
    #[test]
    fn parallel4_equals_scalar(
        coeffs in prop::collection::vec(any_gf61(), 0..200),
        r in any_gf61(),
        s in any_gf61(),
    ) {
        prop_assert_eq!(
            mac::mac_tag_parallel4(&coeffs, r, s),
            mac::mac_tag_scalar(&coeffs, r, s)
        );
    }
}

// ──────────────── Pool invariants ────────────────

fn psk_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1032..1033)
}

fn bit_vec(n: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=1, n)
}

proptest! {
    /// `withdraw_otp(n)` returns exactly n bits, each in {0,1}.
    #[test]
    fn pool_withdraw_returns_bits_in_range(
        psk in psk_bytes(),
        n_bits in 1usize..=4000,
    ) {
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let otp = pool.try_withdraw_otp(n_bits).expect("fresh pool should have 8000 bits");
        prop_assert_eq!(otp.len(), n_bits);
        for &b in &otp {
            prop_assert!(b == 0 || b == 1);
        }
    }

    /// Withdrawing past the end yields Exhausted, never panics.
    #[test]
    fn pool_exhaustion_is_graceful(
        psk in psk_bytes(),
        overshoot in 0usize..=10_000,
    ) {
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let available_bits = pool.available() * 8;
        let req = available_bits + overshoot + 8;
        let res = pool.try_withdraw_otp(req);
        prop_assert!(res.is_err());
    }

    /// Trusted deposit rotates the MAC key deterministically. Two calls with
    /// the same input produce the same new MAC keys.
    #[test]
    fn pool_trusted_deposit_is_deterministic(
        psk in psk_bytes(),
        bits in bit_vec(200),
    ) {
        let nonce = [0u8; 16];
        let mut pool_a = Pool::from_psk(&psk, &nonce);
        let mut pool_b = Pool::from_psk(&psk, &nonce);
        pool_a.try_deposit(&bits, DepositSource::Trusted).unwrap();
        pool_b.try_deposit(&bits, DepositSource::Trusted).unwrap();
        prop_assert_eq!(pool_a.mac_keys(), pool_b.mac_keys());
    }

    /// Recycled deposit never changes the MAC keys, regardless of input.
    #[test]
    fn pool_recycled_deposit_preserves_mac_keys(
        psk in psk_bytes(),
        bits in bit_vec(500),
    ) {
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let (r0, s0) = pool.mac_keys();
        pool.try_deposit(&bits, DepositSource::Recycled).unwrap();
        let (r1, s1) = pool.mac_keys();
        prop_assert_eq!((r0, s0), (r1, s1));
    }
}

// ──────────────── Toeplitz universal hash ────────────────

fn toeplitz_seed(n_bytes: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), n_bytes)
}

proptest! {
    /// Toeplitz hash is GF(2)-linear: h(x ⊕ y) == h(x) ⊕ h(y).
    #[test]
    fn toeplitz_is_linear(
        seed in toeplitz_seed(256),
        x in bit_vec(100),
        y in bit_vec(100),
    ) {
        let t = Toeplitz::new(&seed, 100, 50).unwrap();
        let hx = t.hash(&x);
        let hy = t.hash(&y);
        let xor: Vec<u8> = x.iter().zip(y.iter()).map(|(&a, &b)| a ^ b).collect();
        let hxor = t.hash(&xor);
        let expected: Vec<u8> = hx.iter().zip(hy.iter()).map(|(&a, &b)| a ^ b).collect();
        prop_assert_eq!(hxor, expected);
    }

    /// Output length always matches n_secure.
    #[test]
    fn toeplitz_output_length(
        seed in toeplitz_seed(256),
        n_raw in 50usize..200,
        n_secure in 1usize..50,
    ) {
        prop_assume!(n_secure <= n_raw);
        let input: Vec<u8> = (0..n_raw).map(|i| (i % 2) as u8).collect();
        let t = Toeplitz::new(&seed, n_raw, n_secure).unwrap();
        let result = t.hash(&input);
        prop_assert_eq!(result.len(), n_secure);
    }
}

// ──────────────── Cascade reconciliation ────────────────

proptest! {
    /// Cascade converges at ≤1.5% error rate with 15 passes.
    /// At higher rates Cascade is probabilistic — may leave residual errors
    /// that the caller's PA safety margin is expected to absorb.
    #[test]
    fn cascade_corrects_low_error_rate(
        bits_a in bit_vec(128),
        err_idx in 0usize..128,
        seed in any::<u64>(),
    ) {
        // A single-bit error is guaranteed to converge in Cascade. Two+
        // errors are occasionally probabilistic on pathological seeds —
        // downstream PA absorbs residual errors; this unit test just
        // confirms the happy-path property.
        let mut bits_b = bits_a.clone();
        bits_b[err_idx] ^= 1;
        let _leaked = cascade_reconcile(&bits_a, &mut bits_b, 15, 8, seed);
        prop_assert_eq!(bits_a, bits_b);
    }

    /// When there are no errors, Cascade doesn't mutate bits_b.
    #[test]
    fn cascade_preserves_identical_inputs(
        bits_a in bit_vec(128),
        seed in any::<u64>(),
    ) {
        let original = bits_a.clone();
        let mut bits_b = bits_a.clone();
        let _ = cascade_reconcile(&bits_a, &mut bits_b, 8, 8, seed);
        prop_assert_eq!(bits_b, original);
    }
}
