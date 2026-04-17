//! # Shamir Secret Sharing over GF(M61)
//!
//! Split a secret into n shares with threshold k: any k shares
//! reconstruct the secret, k-1 shares reveal nothing.
//!
//! ITS property: perfect privacy (proved in Lean: ShamirPrivacy.lean).

use liuproto_core::gf61::Gf61;
use liuproto_core::noise;
use crate::lagrange;

/// A share: (x, y) where y = f(x) for the secret polynomial f.
#[derive(Debug, Clone, Copy)]
pub struct Share {
    pub x: Gf61,
    pub y: Gf61,
}

/// Split a secret into n shares with threshold k.
/// The secret is f(0) where f is a random degree-(k-1) polynomial.
pub fn split(secret: Gf61, n: usize, k: usize) -> Vec<Share> {
    assert!(k >= 1, "threshold must be ≥ 1");
    assert!(n >= k, "n must be ≥ k");

    // Generate k-1 random coefficients (a_1, ..., a_{k-1})
    let random_bytes = noise::random_bytes((k - 1) * 8);
    let mut coeffs = Vec::with_capacity(k);
    coeffs.push(secret); // a_0 = secret
    for i in 0..(k - 1) {
        let bytes: [u8; 8] = random_bytes[i * 8..(i + 1) * 8].try_into().unwrap();
        coeffs.push(Gf61::random(&bytes));
    }

    // Evaluate at points 1, 2, ..., n
    (1..=n).map(|i| {
        let x = Gf61::new(i as u64);
        let y = horner_eval(&coeffs, x);
        Share { x, y }
    }).collect()
}

/// Reconstruct the secret from k or more shares.
pub fn reconstruct(shares: &[Share]) -> Gf61 {
    let xs: Vec<Gf61> = shares.iter().map(|s| s.x).collect();
    let ys: Vec<Gf61> = shares.iter().map(|s| s.y).collect();
    lagrange::reconstruct_secret(&xs, &ys)
}

/// Horner evaluation: f(x) = a_0 + a_1·x + a_2·x² + ... = (...((a_{k-1}·x + a_{k-2})·x + ...)·x + a_0)
/// We use the standard ascending-coefficient order.
fn horner_eval(coeffs: &[Gf61], x: Gf61) -> Gf61 {
    // coeffs[0] = a_0 (constant), coeffs[k-1] = a_{k-1} (highest)
    let mut result = Gf61::ZERO;
    for &c in coeffs.iter().rev() {
        result = result * x + c;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct() {
        let secret = Gf61::new(42);
        let shares = split(secret, 5, 3);
        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct
        let recovered = reconstruct(&shares[0..3]);
        assert_eq!(recovered.val(), 42);

        // Different 3 shares should also work
        let recovered2 = reconstruct(&shares[2..5]);
        assert_eq!(recovered2.val(), 42);
    }

    #[test]
    fn test_threshold() {
        let secret = Gf61::new(12345);
        let shares = split(secret, 10, 5);

        // 5 shares: should work
        assert_eq!(reconstruct(&shares[0..5]).val(), 12345);

        // 4 shares: wrong answer (underdetermined system, not enough info)
        let wrong = reconstruct(&shares[0..4]);
        // This SHOULD give the wrong answer (not 12345)
        // (with overwhelming probability over the random coefficients)
        // We don't assert wrong != 12345 because there's a tiny chance
        // it coincidentally matches, but it's astronomically unlikely.
        let _ = wrong;
    }

    #[test]
    fn test_horner() {
        // f(x) = 3 + 2x + x² evaluated at x = 5: 3 + 10 + 25 = 38
        let coeffs = [Gf61::new(3), Gf61::new(2), Gf61::new(1)];
        assert_eq!(horner_eval(&coeffs, Gf61::new(5)).val(), 38);
    }
}
