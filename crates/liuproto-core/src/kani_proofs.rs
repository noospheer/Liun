//! # Kani proof harnesses (proof-of-feasibility for Rust ↔ Lean correspondence)
//!
//! [Kani](https://github.com/model-checking/kani) is a bit-precise model
//! checker for Rust. It exhaustively explores all inputs up to a bound and
//! proves absence of panics, overflows, assertion violations.
//!
//! This file contains a small set of harnesses demonstrating that key
//! `liuproto-core` primitives can be formally verified for specific
//! properties. They're gated on `#[cfg(kani)]` so they only compile under
//! Kani; normal `cargo build` / `cargo test` ignores them entirely.
//!
//! ## Running
//!
//! Install Kani:
//! ```text
//! cargo install --locked kani-verifier
//! cargo kani setup
//! ```
//!
//! Run these harnesses:
//! ```text
//! cargo kani --harness kani_proofs::gf61_add_in_range
//! cargo kani --harness kani_proofs::gf61_mul_in_range
//! cargo kani --harness kani_proofs::mac_tag_never_panics
//! ```
//!
//! ## Why these harnesses?
//!
//! The Lean proofs (`LiupProofs/`) prove the *algorithm* is correct — e.g.
//! Horner's rule correctly evaluates the MAC polynomial, Schwartz-Zippel
//! bounds forgery probability, etc. Kani proves the *Rust code* does what
//! the algorithm says and never panics on any input.
//!
//! Closing the gap between "algorithm correct" (Lean) and "implementation
//! correct" (Rust) for the full codebase is a long-term goal. These
//! harnesses are a demonstration that the approach is feasible, not a
//! claim of full correspondence.

#![cfg(kani)]

use crate::gf61::{Gf61, M61};
use crate::mac::mac_tag;

/// Every `add` output is in `[0, M61)`. Kani verifies this for all inputs
/// in the range up to the bound.
#[kani::proof]
#[kani::unwind(1)]
fn gf61_add_in_range() {
    let a_raw: u64 = kani::any();
    let b_raw: u64 = kani::any();
    kani::assume(a_raw < M61);
    kani::assume(b_raw < M61);
    let a = Gf61::from_raw(a_raw);
    let b = Gf61::from_raw(b_raw);
    let c = a + b;
    assert!(c.val() < M61);
}

/// Every `sub` output is in `[0, M61)`.
#[kani::proof]
#[kani::unwind(1)]
fn gf61_sub_in_range() {
    let a_raw: u64 = kani::any();
    let b_raw: u64 = kani::any();
    kani::assume(a_raw < M61);
    kani::assume(b_raw < M61);
    let c = Gf61::from_raw(a_raw) - Gf61::from_raw(b_raw);
    assert!(c.val() < M61);
}

/// Every `mul` output is in `[0, M61)`.
#[kani::proof]
#[kani::unwind(1)]
fn gf61_mul_in_range() {
    let a_raw: u64 = kani::any();
    let b_raw: u64 = kani::any();
    kani::assume(a_raw < M61);
    kani::assume(b_raw < M61);
    let c = Gf61::from_raw(a_raw) * Gf61::from_raw(b_raw);
    assert!(c.val() < M61);
}

/// `neg(x) + x == 0` for all x.
#[kani::proof]
#[kani::unwind(1)]
fn gf61_neg_is_add_inverse() {
    let x_raw: u64 = kani::any();
    kani::assume(x_raw < M61);
    let x = Gf61::from_raw(x_raw);
    assert!((x + (-x)).val() == 0);
}

/// `mac_tag` on a small coefficient vector never panics and produces an
/// in-range Gf61.
#[kani::proof]
#[kani::unwind(5)]
fn mac_tag_never_panics() {
    let c0: u64 = kani::any();
    let c1: u64 = kani::any();
    let c2: u64 = kani::any();
    let r: u64 = kani::any();
    let s: u64 = kani::any();
    kani::assume(c0 < M61 && c1 < M61 && c2 < M61 && r < M61 && s < M61);
    let coeffs = [
        Gf61::from_raw(c0),
        Gf61::from_raw(c1),
        Gf61::from_raw(c2),
    ];
    let tag = mac_tag(&coeffs, Gf61::from_raw(r), Gf61::from_raw(s));
    assert!(tag.val() < M61);
}
