//! # liun-consensus: Trust-Weighted BFT Consensus
//!
//! Accepts blocks/transactions when attesting trust exceeds 2/3 threshold.
//! Uses personalized PageRank trust scores from the Liu channel graph.

pub mod committee;

use liuproto_core::gf61::Gf61;
use std::collections::HashMap;

/// A signed message with USS threshold signature.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub message: u64,
    pub signature: Gf61,
    pub signer_committee: Vec<u64>,
}

/// An attestation from a node that verified the signature.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub node_id: u64,
    pub verified: bool,
}

/// Consensus decision for a signed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accepted,
    Rejected,
    Pending,
}

/// Check if attestations reach the 2/3 trust threshold.
pub fn check_consensus(
    attestations: &[Attestation],
    trust_scores: &HashMap<u64, f64>,
    threshold: f64,
) -> Decision {
    let attesting_trust: f64 = attestations.iter()
        .filter(|a| a.verified)
        .filter_map(|a| trust_scores.get(&a.node_id))
        .sum();

    let total_trust: f64 = trust_scores.values().sum();
    let required = threshold * total_trust;

    if attesting_trust >= required {
        Decision::Accepted
    } else {
        // Check if enough remaining trust could still push it over
        let rejecting_trust: f64 = attestations.iter()
            .filter(|a| !a.verified)
            .filter_map(|a| trust_scores.get(&a.node_id))
            .sum();
        if rejecting_trust > total_trust - required {
            Decision::Rejected
        } else {
            Decision::Pending
        }
    }
}

/// Default BFT threshold: 2/3.
pub const BFT_THRESHOLD: f64 = 2.0 / 3.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_accepted() {
        let mut trust = HashMap::new();
        trust.insert(1, 0.3);
        trust.insert(2, 0.3);
        trust.insert(3, 0.2);
        trust.insert(4, 0.2);

        // Nodes 1, 2, 3 attest (trust = 0.8 > 2/3)
        let attestations = vec![
            Attestation { node_id: 1, verified: true },
            Attestation { node_id: 2, verified: true },
            Attestation { node_id: 3, verified: true },
        ];

        assert_eq!(check_consensus(&attestations, &trust, BFT_THRESHOLD), Decision::Accepted);
    }

    #[test]
    fn test_consensus_rejected() {
        let mut trust = HashMap::new();
        trust.insert(1, 0.3);
        trust.insert(2, 0.3);
        trust.insert(3, 0.2);
        trust.insert(4, 0.2);

        // Nodes 1, 2, 3 reject (trust = 0.8 > 1/3 rejecting)
        let attestations = vec![
            Attestation { node_id: 1, verified: false },
            Attestation { node_id: 2, verified: false },
            Attestation { node_id: 3, verified: false },
            Attestation { node_id: 4, verified: false },
        ];

        assert_eq!(check_consensus(&attestations, &trust, BFT_THRESHOLD), Decision::Rejected);
    }
}
