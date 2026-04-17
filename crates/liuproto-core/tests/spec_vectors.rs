//! Spec-level test vectors.
//!
//! Hand-computed expected outputs for deterministic primitives (GF(2⁶¹−1)
//! arithmetic, Wegman-Carter MAC via Horner's rule, modular reduction),
//! derived independently from the underlying math rather than from any
//! reference implementation's output. Both our Rust and the Python Liup
//! reference can be checked against these vectors — if either deviates,
//! the spec vectors say which side is wrong.
//!
//! Each test group is annotated with the math it's verifying.

use liuproto_core::gf61::Gf61;
use liuproto_core::mac::{mac_tag, mac_verify};
use liuproto_core::noise::mod_reduce;

/// M61 = 2^61 - 1 = 2305843009213693951.
const M61: u64 = (1u64 << 61) - 1;

// ──────────────── GF(2⁶¹−1) arithmetic ────────────────

#[test]
fn spec_gf61_add_in_range() {
    // 5 + 7 = 12 (no wrap)
    assert_eq!((Gf61::new(5) + Gf61::new(7)).val(), 12);
    // (M61 - 1) + 1 = 0 (wraps once)
    assert_eq!((Gf61::new(M61 - 1) + Gf61::new(1)).val(), 0);
    // (M61 - 1) + (M61 - 1) = M61 - 2 (wraps once)
    assert_eq!((Gf61::new(M61 - 1) + Gf61::new(M61 - 1)).val(), M61 - 2);
}

#[test]
fn spec_gf61_mul_in_range() {
    // 10 * 20 = 200
    assert_eq!((Gf61::new(10) * Gf61::new(20)).val(), 200);
    // 0 * anything = 0
    assert_eq!((Gf61::new(0) * Gf61::new(M61 - 1)).val(), 0);
    // 1 * x = x
    assert_eq!((Gf61::new(1) * Gf61::new(123456789)).val(), 123456789);
    // (M61 - 1)² ≡ 1 (mod M61), since M61 - 1 ≡ -1.
    assert_eq!((Gf61::new(M61 - 1) * Gf61::new(M61 - 1)).val(), 1);
    // 2^31 * 2^31 = 2^62 = 2 * M61 + 2, so = 2 (mod M61).
    assert_eq!((Gf61::new(1 << 31) * Gf61::new(1 << 31)).val(), 2);
}

#[test]
fn spec_gf61_sub() {
    // 7 - 5 = 2
    assert_eq!((Gf61::new(7) - Gf61::new(5)).val(), 2);
    // 0 - 1 ≡ M61 - 1
    assert_eq!((Gf61::new(0) - Gf61::new(1)).val(), M61 - 1);
}

#[test]
fn spec_gf61_zero_identity() {
    for &x in &[0u64, 1, 42, 1u64 << 30, M61 - 1] {
        assert_eq!((Gf61::new(x) + Gf61::ZERO).val(), x);
    }
}

// ──────────────── Wegman-Carter MAC (Horner's rule) ────────────────

/// Hand-traced Horner evaluation:
/// tag = s + c[0]*r^(n-1) + c[1]*r^(n-2) + ... + c[n-1]
///     = s + ((...((c[0]*r + c[1])*r + c[2])*r + ...)*r + c[n-1])
#[test]
fn spec_mac_empty_coeffs_equals_s() {
    // h = 0 (empty loop); tag = 0 + s = s.
    let tag = mac_tag(&[], Gf61::new(42), Gf61::new(7));
    assert_eq!(tag.val(), 7);
}

#[test]
fn spec_mac_single_coeff() {
    // coeffs = [c]; h = 0*r + c = c; tag = c + s.
    let tag = mac_tag(&[Gf61::new(3)], Gf61::new(10), Gf61::new(5));
    assert_eq!(tag.val(), 8); // 3 + 5
}

#[test]
fn spec_mac_three_coeffs_simple() {
    // coeffs = [1, 2, 3], r = 10, s = 0.
    // h = 0; h = 0*10 + 1 = 1; h = 1*10 + 2 = 12; h = 12*10 + 3 = 123.
    // tag = 123 + 0 = 123.
    let tag = mac_tag(
        &[Gf61::new(1), Gf61::new(2), Gf61::new(3)],
        Gf61::new(10),
        Gf61::new(0),
    );
    assert_eq!(tag.val(), 123);
}

#[test]
fn spec_mac_with_nonzero_s() {
    // Same coefficients as above but s = 100.
    // tag = 123 + 100 = 223.
    let tag = mac_tag(
        &[Gf61::new(1), Gf61::new(2), Gf61::new(3)],
        Gf61::new(10),
        Gf61::new(100),
    );
    assert_eq!(tag.val(), 223);
}

#[test]
fn spec_mac_verify_roundtrip() {
    let coeffs = [Gf61::new(11), Gf61::new(22), Gf61::new(33), Gf61::new(44)];
    let r = Gf61::new(7);
    let s = Gf61::new(1);
    let tag = mac_tag(&coeffs, r, s);
    assert!(mac_verify(&coeffs, r, s, tag));
    // Flip s → verify fails.
    assert!(!mac_verify(&coeffs, r, s + Gf61::new(1), tag));
}

#[test]
fn spec_mac_wraps_correctly() {
    // Need ≥ 2 coefficients to exercise the multiplication-by-r step.
    // coeffs = [2^30, 0], r = 2^30, s = 0.
    // h = 0; h = 0*r + 2^30 = 2^30; h = 2^30 * 2^30 + 0 = 2^60.
    // 2^60 < M61 so no wrap; tag = 2^60.
    let tag = mac_tag(
        &[Gf61::new(1 << 30), Gf61::new(0)],
        Gf61::new(1 << 30), Gf61::new(0),
    );
    assert_eq!(tag.val(), 1u64 << 60);

    // coeffs = [2^31, 0], r = 2^31, s = 0.
    // h = 2^31; h = 2^31 * 2^31 + 0 = 2^62 ≡ 2 (mod M61).
    // tag = 2.
    let tag = mac_tag(
        &[Gf61::new(1 << 31), Gf61::new(0)],
        Gf61::new(1 << 31), Gf61::new(0),
    );
    assert_eq!(tag.val(), 2);
}

// ──────────────── Modular reduction (wire values) ────────────────
//
// `mod_reduce(x, p) = x - p * round(x/p)`, mapping x into the half-open
// interval `(-p/2, p/2]`. f64 rounding is "round half away from zero"
// so 0.5 rounds to 1.0 and -0.5 rounds to -1.0.

#[test]
fn spec_mod_reduce_small_values() {
    // In range: no change.
    assert!((mod_reduce(0.3, 1.0) - 0.3).abs() < 1e-12);
    assert!((mod_reduce(-0.4, 1.0) - (-0.4)).abs() < 1e-12);
    // Just above p/2: wraps.
    assert!((mod_reduce(0.7, 1.0) - (-0.3)).abs() < 1e-12);
    // Just below -p/2: wraps the other way.
    assert!((mod_reduce(-0.7, 1.0) - 0.3).abs() < 1e-12);
    // Multiples of p: reduce to 0.
    assert!((mod_reduce(3.0, 1.0) - 0.0).abs() < 1e-12);
    assert!((mod_reduce(-5.0, 1.0) - 0.0).abs() < 1e-12);
}

#[test]
fn spec_mod_reduce_range_invariant() {
    let p = 2.5_f64;
    for k in -100..=100 {
        let x = k as f64 * 0.1_f64;
        let r = mod_reduce(x, p);
        assert!(r > -p / 2.0 - 1e-9 && r <= p / 2.0 + 1e-9,
            "mod_reduce({x}, {p}) = {r} out of (-p/2, p/2]");
    }
}

#[test]
fn spec_mod_reduce_idempotent() {
    // mod_reduce of a reduced value is unchanged.
    let p = 3.0;
    for x in [0.0, 0.5, 1.2, -0.7, -1.4, 1.5, -1.5] {
        let r = mod_reduce(x, p);
        let r2 = mod_reduce(r, p);
        assert!((r - r2).abs() < 1e-12, "mod_reduce not idempotent: {r} → {r2}");
    }
}
