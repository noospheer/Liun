//! # GF(M61): Mersenne Prime Field Arithmetic
//!
//! All protocol arithmetic operates over GF(M61) where M61 = 2^61 - 1.
//! This is a prime field with fast modular reduction via the Mersenne property:
//! 2^61 ≡ 1 (mod M61), so reduction is shift + mask + conditional subtract.
//!
//! The same field is used for:
//! - Wegman-Carter MAC (polynomial evaluation)
//! - Shamir secret sharing (polynomial evaluation)
//! - USS signatures (polynomial evaluation + Lagrange interpolation)
//!
//! Performance: Rust's native u128 gives single-instruction multiply,
//! matching the C `__uint128_t` extension from the Python implementation.
//!
//! ## Constant-time discipline
//!
//! All arithmetic ops (`add`, `sub`, `mul`, `neg`) are **branchless in the
//! secret data**. The modular reduction step that would otherwise be
//! `if x >= M61 { x - M61 } else { x }` is written as a branchless CMOV-style
//! mask:
//!
//! ```ignore
//! let (diff, underflow) = x.overflowing_sub(M61);
//! let mask = (underflow as u64).wrapping_neg();
//! x_reduced = (x & mask) | (diff & !mask)
//! ```
//!
//! This ensures MAC computation and other polynomial evaluations don't
//! leak intermediate value magnitudes via data-dependent branches.
//! `pow`/`inv` are variable-time (input is public: always `M61-2` for inv
//! and never a secret for pow), so they use the simpler branching form.
//!
//! ITS property: Schwartz-Zippel (polynomial root bound ≤ degree)
//! is proved in Lean 4 (SchwartzZippel.lean, zero sorry).

/// The Mersenne prime M61 = 2^61 - 1.
pub const M61: u64 = (1u64 << 61) - 1;

/// A field element in GF(M61). Always reduced to [0, M61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gf61(u64);

impl Gf61 {
    /// Create a field element, reducing modulo M61.
    #[inline]
    pub fn new(val: u64) -> Self {
        let reduced = val % M61;
        // M61 % M61 = 0, but we want 0 not M61
        Self(if reduced == M61 { 0 } else { reduced })
    }

    /// Create from a raw value already known to be in [0, M61).
    /// # Safety
    /// Caller must ensure val < M61.
    #[inline]
    pub const fn from_raw(val: u64) -> Self {
        Self(val)
    }

    /// The zero element.
    pub const ZERO: Self = Self(0);

    /// The one element.
    pub const ONE: Self = Self(1);

    /// Get the raw u64 value.
    #[inline]
    pub const fn val(self) -> u64 {
        self.0
    }

    /// Branchless conditional reduction: if `s >= M61`, return `s - M61`, else `s`.
    /// Runs in constant time regardless of `s`.
    #[inline(always)]
    fn reduce(s: u64) -> u64 {
        let (diff, underflow) = s.overflowing_sub(M61);
        // underflow=true iff s < M61 → we want s.
        // underflow=false iff s >= M61 → we want diff.
        let mask = (underflow as u64).wrapping_neg(); // 0xFF.. if underflow, else 0
        (s & mask) | (diff & !mask)
    }

    /// Addition modulo M61. Branchless in the secret data.
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        // Both < M61, so s < 2*M61 and fits in u64.
        Self(Self::reduce(self.0 + rhs.0))
    }

    /// Subtraction modulo M61. Branchless in the secret data.
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        // Add M61 first to avoid underflow.
        Self(Self::reduce(self.0.wrapping_sub(rhs.0).wrapping_add(M61)))
    }

    /// Multiplication modulo M61 using u128. Branchless in the secret data.
    ///
    /// The Mersenne property gives fast reduction:
    /// For product p = a * b (up to 122 bits):
    ///   p mod M61 = (p & M61) + (p >> 61)
    /// with at most one conditional subtract — which we do branchlessly.
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        let p = (self.0 as u128) * (rhs.0 as u128);
        let lo = (p as u64) & M61;
        let hi = (p >> 61) as u64;
        Self(Self::reduce(lo + hi))
    }

    /// Negation: -a = M61 - a. Branchless in `self.0`.
    #[inline]
    pub fn neg(self) -> Self {
        // When self.0 == 0: we want 0. M61 - 0 == M61 which is ≡ 0.
        // Run it through reduce to collapse M61 → 0.
        Self(Self::reduce(M61 - self.0))
    }

    /// Exponentiation by squaring.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Multiplicative inverse via Fermat's little theorem: a^(-1) = a^(M61-2).
    #[inline]
    pub fn inv(self) -> Self {
        assert!(self.0 != 0, "division by zero in GF(M61)");
        self.pow(M61 - 2)
    }

    /// Division: a / b = a * b^(-1).
    #[inline]
    pub fn div(self, rhs: Self) -> Self {
        self.mul(rhs.inv())
    }

    /// Generate a uniform random element from 8 bytes of entropy.
    pub fn random(bytes: &[u8; 8]) -> Self {
        let val = u64::from_le_bytes(*bytes);
        Self::new(val)
    }
}

// Implement standard traits for ergonomic use.

impl std::ops::Add for Gf61 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self { Gf61::add(self, rhs) }
}

impl std::ops::Sub for Gf61 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self { Gf61::sub(self, rhs) }
}

impl std::ops::Mul for Gf61 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self { Gf61::mul(self, rhs) }
}

impl std::ops::Neg for Gf61 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self { Gf61::neg(self) }
}

impl std::fmt::Display for Gf61 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Gf61 {
    fn from(val: u64) -> Self { Self::new(val) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = Gf61::new(42);
        let b = Gf61::new(17);

        assert_eq!((a + b).val(), 59);
        assert_eq!((a - b).val(), 25);
        assert_eq!((a * b).val(), 714);
        assert_eq!((a + Gf61::ZERO).val(), 42);
        assert_eq!((a * Gf61::ONE).val(), 42);
    }

    #[test]
    fn test_mersenne_reduction() {
        // M61 should reduce to 0
        assert_eq!(Gf61::new(M61).val(), 0);
        // M61 + 1 should reduce to 1
        assert_eq!(Gf61::new(M61 + 1).val(), 1);
    }

    #[test]
    fn test_inverse() {
        let a = Gf61::new(42);
        let a_inv = a.inv();
        assert_eq!((a * a_inv).val(), 1);
    }

    #[test]
    fn test_negation() {
        let a = Gf61::new(42);
        assert_eq!((a + (-a)).val(), 0);
        assert_eq!((-Gf61::ZERO).val(), 0);
    }

    #[test]
    fn test_pow() {
        let a = Gf61::new(2);
        // 2^10 = 1024
        assert_eq!(a.pow(10).val(), 1024);
        // 2^61 ≡ 1 (mod M61) — Fermat's little: a^(p-1) = 1
        // Actually 2^61 = M61 + 1 ≡ 1 (mod M61)
        assert_eq!(a.pow(61).val(), 1);
    }

    #[test]
    fn test_large_multiply() {
        // Near-max values to test u128 reduction
        let a = Gf61::new(M61 - 1);
        let b = Gf61::new(M61 - 1);
        let c = a * b;
        // (M61-1)^2 mod M61 = (-1)^2 mod M61 = 1
        assert_eq!(c.val(), 1);
    }
}
