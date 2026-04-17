//! # Threshold Signing
//!
//! Each signer holds one share (x_i, F(x_i)) of the signing polynomial.
//! To sign message m, k signers compute partial signatures and combine
//! via Lagrange interpolation to produce σ = F(m).

use liuproto_core::gf61::Gf61;
use crate::lagrange;

/// A partial signer holding one share of the signing polynomial.
pub struct PartialSigner {
    /// Node ID (= evaluation point x_i).
    pub node_id: u64,
    /// Share value F(node_id).
    pub share: Gf61,
}

impl PartialSigner {
    pub fn new(node_id: u64, share: Gf61) -> Self {
        Self { node_id, share }
    }

    /// Compute partial signature: share · L_i(message).
    pub fn partial_sign(&self, message: Gf61, committee_ids: &[u64]) -> Gf61 {
        let xs: Vec<Gf61> = committee_ids.iter().map(|&id| Gf61::new(id)).collect();
        let i = committee_ids.iter().position(|&id| id == self.node_id)
            .expect("signer not in committee");
        let basis = lagrange::lagrange_basis(&xs, i, message);
        self.share * basis
    }
}

/// Combine partial signatures into a full signature σ = F(message).
pub fn combine_signatures(partials: &[Gf61]) -> Gf61 {
    let mut result = Gf61::ZERO;
    for &p in partials {
        result = result + p;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;

    #[test]
    fn test_threshold_sign_verify() {
        // Secret polynomial of degree 2 (threshold k=3)
        let secret = Gf61::new(42);
        let shares = shamir::split(secret, 5, 3);

        // Committee: nodes 1, 2, 3 (first 3 shares)
        let committee_ids: Vec<u64> = shares[0..3].iter().map(|s| s.x.val()).collect();
        let signers: Vec<PartialSigner> = shares[0..3].iter()
            .map(|s| PartialSigner::new(s.x.val(), s.y))
            .collect();

        // Sign message m = 100
        let message = Gf61::new(100);
        let partials: Vec<Gf61> = signers.iter()
            .map(|s| s.partial_sign(message, &committee_ids))
            .collect();
        let signature = combine_signatures(&partials);

        // Verify: σ should equal F(100) where F is the secret polynomial.
        // We can check by interpolating all 5 shares at x=100.
        let xs: Vec<Gf61> = shares.iter().map(|s| s.x).collect();
        let ys: Vec<Gf61> = shares.iter().map(|s| s.y).collect();
        let expected = lagrange::interpolate(&xs, &ys, message);

        assert_eq!(signature.val(), expected.val());
    }
}
