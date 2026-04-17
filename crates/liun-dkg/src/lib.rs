//! # liun-dkg: Distributed Key Generation
//!
//! Threshold DKG over ITS channels: n nodes collectively generate
//! a degree-d signing polynomial F without any single node seeing F.
//!
//! Protocol:
//! 1. Each node generates random degree-d polynomial fᵢ
//! 2. Shares fᵢ(j) sent to each node j over ITS channels
//! 3. Consistency verification detects corrupt senders
//! 4. Combined shares sⱼ = Σ fᵢ(j) form the signing polynomial
//!
//! ITS privacy: t < k corrupt nodes learn nothing about F(0).
//! Proved in Lean (DKGComposed.lean, ShamirPrivacy.lean).

use liuproto_core::gf61::Gf61;
use liun_uss::shamir::{self, Share};
use liun_uss::lagrange;

/// Parameters for a DKG round.
#[derive(Debug, Clone)]
pub struct DkgParams {
    /// Total number of nodes.
    pub n: usize,
    /// Signing threshold k = 2n/3 + 1.
    pub threshold: usize,
    /// Polynomial degree d = k - 1.
    pub degree: usize,
}

impl DkgParams {
    pub fn new(n: usize) -> Self {
        let threshold = 2 * n / 3 + 1;
        Self {
            n,
            threshold,
            degree: threshold - 1,
        }
    }

    /// Maximum tolerable corrupt nodes.
    pub fn max_corrupt(&self) -> usize {
        (self.n - 1) / 3
    }

    /// Maximum signatures per epoch.
    pub fn signature_budget(&self) -> usize {
        self.degree / 2
    }
}

/// A node's contribution to the DKG: a random polynomial.
pub struct Contribution {
    /// The node that generated this contribution.
    pub sender_id: u64,
    /// Shares: fᵢ(j) for each node j.
    pub shares: Vec<Share>,
}

impl Contribution {
    /// Generate a random contribution with the given secret (fᵢ(0)).
    /// In practice, the secret is random; for DKG, each node picks
    /// their own random f_i(0).
    pub fn generate(sender_id: u64, secret: Gf61, params: &DkgParams) -> Self {
        let shares = shamir::split(secret, params.n, params.threshold);
        Self { sender_id, shares }
    }

    /// Get the share for a specific recipient.
    pub fn share_for(&self, recipient_idx: usize) -> Share {
        self.shares[recipient_idx]
    }
}

/// The DKG protocol state for one node.
pub struct Dkg {
    /// Our node index (0-based).
    pub node_idx: usize,
    /// Protocol parameters.
    pub params: DkgParams,
    /// Received shares from each sender (sender_idx → Share).
    received: Vec<Option<Share>>,
    /// Our own contribution.
    our_contribution: Option<Contribution>,
    /// Excluded (detected corrupt) senders.
    excluded: Vec<bool>,
}

impl Dkg {
    pub fn new(node_idx: usize, params: DkgParams) -> Self {
        let n = params.n;
        Self {
            node_idx,
            params,
            received: vec![None; n],
            our_contribution: None,
            excluded: vec![false; n],
        }
    }

    /// Step 1: Generate our contribution.
    pub fn generate_contribution(&mut self) -> &Contribution {
        let secret_bytes = liuproto_core::noise::random_bytes(8);
        let secret = Gf61::random(&secret_bytes.try_into().unwrap());
        let contrib = Contribution::generate(
            self.node_idx as u64,
            secret,
            &self.params,
        );
        self.our_contribution = Some(contrib);
        self.our_contribution.as_ref().unwrap()
    }

    /// Step 2: Receive a share from a sender.
    pub fn receive_share(&mut self, sender_idx: usize, share: Share) {
        self.received[sender_idx] = Some(share);
    }

    /// Step 3: Verify consistency of shares from a sender.
    /// Given all shares this sender distributed, check they lie
    /// on a degree-d polynomial.
    pub fn verify_sender(&mut self, sender_idx: usize, all_shares: &[Share]) -> bool {
        if all_shares.len() <= self.params.degree + 1 {
            return true; // not enough points to over-determine
        }

        // Interpolate first d+1 points, check remaining
        let k = self.params.degree + 1;
        let basis_x: Vec<Gf61> = all_shares[..k].iter().map(|s| s.x).collect();
        let basis_y: Vec<Gf61> = all_shares[..k].iter().map(|s| s.y).collect();

        for share in &all_shares[k..] {
            let expected = lagrange::interpolate(&basis_x, &basis_y, share.x);
            if expected != share.y {
                self.excluded[sender_idx] = true;
                return false;
            }
        }
        true
    }

    /// Step 4: Combine shares from non-excluded senders.
    /// Returns our combined share sⱼ = Σᵢ fᵢ(j) for the signing polynomial.
    pub fn combine(&self) -> Share {
        let x = Gf61::new((self.node_idx + 1) as u64);
        let mut y = Gf61::ZERO;

        for (i, share_opt) in self.received.iter().enumerate() {
            if self.excluded[i] {
                continue;
            }
            if let Some(share) = share_opt {
                y = y + share.y;
            }
        }

        Share { x, y }
    }

    /// Check if a sender is excluded.
    pub fn is_excluded(&self, sender_idx: usize) -> bool {
        self.excluded[sender_idx]
    }

    /// Number of non-excluded senders.
    pub fn honest_count(&self) -> usize {
        self.excluded.iter().filter(|&&e| !e).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_params() {
        let p = DkgParams::new(100);
        assert_eq!(p.threshold, 67);
        assert_eq!(p.degree, 66);
        assert_eq!(p.max_corrupt(), 33);
        assert_eq!(p.signature_budget(), 33);
    }

    #[test]
    fn test_dkg_full_protocol() {
        let n = 5;
        let params = DkgParams::new(n);
        // threshold = 4, degree = 3

        // Each node generates a contribution
        let mut contributions: Vec<Contribution> = Vec::new();
        for i in 0..n {
            let secret_bytes = liuproto_core::noise::random_bytes(8);
            let secret = Gf61::random(&secret_bytes.try_into().unwrap());
            contributions.push(Contribution::generate(i as u64, secret, &params));
        }

        // Each node receives shares from all senders
        let mut dkgs: Vec<Dkg> = (0..n)
            .map(|i| Dkg::new(i, params.clone()))
            .collect();

        for sender_idx in 0..n {
            for recv_idx in 0..n {
                let share = contributions[sender_idx].share_for(recv_idx);
                dkgs[recv_idx].receive_share(sender_idx, share);
            }
        }

        // Combine
        let combined_shares: Vec<Share> = dkgs.iter().map(|d| d.combine()).collect();

        // The combined secret F(0) = Σ fᵢ(0)
        let expected_secret: Gf61 = contributions.iter()
            .map(|c| c.shares[0].y) // share at x=1, not x=0...
            .fold(Gf61::ZERO, |acc, _| acc); // wrong, let me fix

        // Actually: F(0) = Σ fᵢ(0), and fᵢ(0) is the secret of each contribution.
        // We can recover F(0) by interpolating the combined shares.
        let xs: Vec<Gf61> = combined_shares.iter().map(|s| s.x).collect();
        let ys: Vec<Gf61> = combined_shares.iter().map(|s| s.y).collect();
        let recovered_f0 = lagrange::reconstruct_secret(&xs, &ys);

        // The true F(0) = sum of individual secrets
        // We need to know each fᵢ(0) — reconstruct from their shares
        let true_f0: Gf61 = contributions.iter().map(|c| {
            let cxs: Vec<Gf61> = c.shares.iter().map(|s| s.x).collect();
            let cys: Vec<Gf61> = c.shares.iter().map(|s| s.y).collect();
            lagrange::reconstruct_secret(&cxs, &cys)
        }).fold(Gf61::ZERO, |acc, s| acc + s);

        assert_eq!(recovered_f0.val(), true_f0.val(),
            "DKG combined polynomial F(0) mismatch");
    }

    #[test]
    fn test_dkg_detects_corrupt() {
        let n = 5;
        let params = DkgParams::new(n);

        // Generate honest contributions
        let mut contributions: Vec<Contribution> = Vec::new();
        for i in 0..n {
            let secret_bytes = liuproto_core::noise::random_bytes(8);
            let secret = Gf61::random(&secret_bytes.try_into().unwrap());
            contributions.push(Contribution::generate(i as u64, secret, &params));
        }

        // Corrupt sender 2: tamper with one share
        let mut corrupt_shares = contributions[2].shares.clone();
        corrupt_shares[3] = Share {
            x: corrupt_shares[3].x,
            y: corrupt_shares[3].y + Gf61::ONE, // tamper
        };

        // Verifier checks all shares from sender 2
        let mut dkg = Dkg::new(0, params);
        let detected = !dkg.verify_sender(2, &corrupt_shares);
        assert!(detected, "corrupt sender not detected");
        assert!(dkg.is_excluded(2));
    }
}
