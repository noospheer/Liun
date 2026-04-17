//! # Deterministic Signature Verification
//!
//! A verifier holds v > d independent evaluation points of F.
//! Given (message, σ), check if the v+1 points lie on a unique
//! degree-d polynomial. This is deterministic — not probabilistic.
//!
//! ITS property: if σ ≠ F(m), detection is certain (not probabilistic).
//! Proved in Lean (USS.lean: uss_verification_deterministic).

use liuproto_core::gf61::Gf61;
use crate::lagrange;

/// A verifier holding evaluation points of the signing polynomial.
pub struct Verifier {
    /// Known evaluation points (x_j, F(x_j)).
    pub points_x: Vec<Gf61>,
    pub points_y: Vec<Gf61>,
    /// Polynomial degree.
    pub degree: usize,
}

impl Verifier {
    pub fn new(points_x: Vec<Gf61>, points_y: Vec<Gf61>, degree: usize) -> Self {
        assert_eq!(points_x.len(), points_y.len());
        assert!(points_x.len() > degree,
            "need > degree points for deterministic verification");
        Self { points_x, points_y, degree }
    }

    /// Verify a signature (message, sigma).
    ///
    /// Uses the first degree+1 known points to interpolate F,
    /// then checks: does F(message) == sigma?
    /// Also cross-checks remaining known points for consistency.
    ///
    /// Returns true iff sigma = F(message) AND all known points
    /// are consistent (lie on the same degree-d polynomial).
    pub fn verify(&self, message: Gf61, sigma: Gf61) -> bool {
        let k = self.degree + 1; // number of points needed

        // Use first k points to define the polynomial
        let basis_x = &self.points_x[..k];
        let basis_y = &self.points_y[..k];

        // Check: does the interpolated polynomial give sigma at message?
        let expected = lagrange::interpolate(basis_x, basis_y, message);
        if expected != sigma {
            return false;
        }

        // Cross-check: remaining known points should be consistent
        for i in k..self.points_x.len() {
            let check = lagrange::interpolate(basis_x, basis_y, self.points_x[i]);
            if check != self.points_y[i] {
                return false; // inconsistency in known points
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;

    #[test]
    fn test_verify_valid_signature() {
        let secret = Gf61::new(99);
        let shares = shamir::split(secret, 7, 3);

        // Verifier holds shares 4, 5, 6, 7 (4 > degree 2)
        let verifier = Verifier::new(
            shares[3..7].iter().map(|s| s.x).collect(),
            shares[3..7].iter().map(|s| s.y).collect(),
            2, // degree
        );

        // Compute true signature via interpolation
        let message = Gf61::new(50);
        let xs: Vec<Gf61> = shares.iter().map(|s| s.x).collect();
        let ys: Vec<Gf61> = shares.iter().map(|s| s.y).collect();
        let sigma = lagrange::interpolate(&xs, &ys, message);

        assert!(verifier.verify(message, sigma));
    }

    #[test]
    fn test_reject_invalid_signature() {
        let secret = Gf61::new(99);
        let shares = shamir::split(secret, 7, 3);

        let verifier = Verifier::new(
            shares[3..7].iter().map(|s| s.x).collect(),
            shares[3..7].iter().map(|s| s.y).collect(),
            2,
        );

        let message = Gf61::new(50);
        let fake_sigma = Gf61::new(12345); // wrong signature
        assert!(!verifier.verify(message, fake_sigma));
    }
}
