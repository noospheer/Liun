//! # liuproto-core: ITS Cryptographic Primitives
//!
//! Core building blocks for the Liu protocol suite:
//! - `gf61`: Mersenne prime field arithmetic (GF(2^61 - 1))
//! - `mac`: Wegman-Carter polynomial MAC (ITS authentication)
//! - `noise`: Gaussian noise generation (Box-Muller from OS entropy)
//! - `pool`: OTP pool with key recycling (ITS key management)
//!
//! All security properties are machine-verified in Lean 4:
//! - MAC forgery ≤ d/M61 (SchwartzZippel.lean)
//! - Pool recycling: constant security forever (XORBias.lean)
//! - TV bound on sign bits (Theorem1.lean)

pub mod endpoint;
pub mod gf61;
pub mod link;
pub mod mac;
pub mod noise;
pub mod entropy;
pub mod pool;
pub mod prewarm;
pub mod privacy_amp;
pub mod reconciliation;
pub mod rng;
pub mod storage;
pub mod identity;

// Formal-verification harnesses — compiled only under Kani.
#[cfg(kani)]
mod kani_proofs;
