//! # liun-uss: Unconditionally Secure Signatures
//!
//! Threshold signatures over GF(M61) using polynomial secret sharing.
//! - `shamir`: split/reconstruct secrets via polynomial evaluation
//! - `lagrange`: interpolation for signature combination + verification
//! - `signer`: partial signing with Lagrange coefficients
//! - `verifier`: deterministic polynomial consistency check
//!
//! ITS property: forgery probability = 1/M61 ≈ 4.3 × 10⁻¹⁹ per attempt.
//! Proved in Lean 4 (USSForgery.lean, ShamirPrivacy.lean).

pub mod lagrange;
pub mod shamir;
pub mod signer;
pub mod verifier;
