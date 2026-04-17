//! # Dynamic Rolling Committee
//!
//! Trust-weighted committee selection with rolling rotation.
//! Committee size is configurable. Each epoch, a fraction of
//! members rotate out (lowest trust or longest tenure) and
//! replacements are selected by trust-weighted sampling.

use liun_overlay::trust::TrustGraph;
use std::collections::{HashMap, HashSet, VecDeque};

/// Committee configuration.
#[derive(Debug, Clone)]
pub struct CommitteeConfig {
    /// Target committee size.
    pub target_size: usize,
    /// Fraction of committee to rotate per epoch (0.0–1.0).
    pub rotation_rate: f64,
    /// Minimum trust score to be eligible for committee.
    pub min_trust: f64,
    /// Damping factor for PageRank.
    pub damping: f64,
    /// PageRank iterations.
    pub iterations: usize,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            target_size: 100,
            rotation_rate: 0.1, // rotate 10% per epoch
            min_trust: 0.001,
            damping: 0.85,
            iterations: 20,
        }
    }
}

/// A committee member with metadata.
#[derive(Debug, Clone)]
pub struct Member {
    pub node_id: u64,
    pub trust: f64,
    /// Epochs served on this committee stretch.
    pub tenure: usize,
}

/// The rolling committee.
pub struct Committee {
    pub config: CommitteeConfig,
    /// Current members in order of admission.
    members: VecDeque<Member>,
    /// Set of current member IDs for fast lookup.
    member_set: HashSet<u64>,
    /// Current epoch number.
    pub epoch: u64,
}

impl Committee {
    /// Create an empty committee.
    pub fn new(config: CommitteeConfig) -> Self {
        Self {
            config,
            members: VecDeque::new(),
            member_set: HashSet::new(),
            epoch: 0,
        }
    }

    /// Initialize the committee from trust scores (first epoch).
    /// Selects the top target_size nodes by trust.
    pub fn initialize(&mut self, trust: &HashMap<u64, f64>) {
        let mut candidates: Vec<(u64, f64)> = trust.iter()
            .filter(|&(_, &t)| t >= self.config.min_trust)
            .map(|(&id, &t)| (id, t))
            .collect();

        // Sort by trust descending
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Take top target_size
        self.members.clear();
        self.member_set.clear();
        for &(id, trust) in candidates.iter().take(self.config.target_size) {
            self.members.push_back(Member { node_id: id, trust, tenure: 0 });
            self.member_set.insert(id);
        }
        self.epoch = 0;
    }

    /// Rotate the committee for a new epoch.
    /// Retires a fraction of members (longest tenure first) and
    /// admits replacements from the eligible pool weighted by trust.
    pub fn rotate(&mut self, trust: &HashMap<u64, f64>, seed: u64) {
        self.epoch += 1;

        // Increment tenure
        for member in &mut self.members {
            member.tenure += 1;
            // Update trust scores
            if let Some(&t) = trust.get(&member.node_id) {
                member.trust = t;
            }
        }

        // How many to rotate out
        let n_rotate = ((self.members.len() as f64 * self.config.rotation_rate).ceil() as usize)
            .max(1)
            .min(self.members.len());

        // Remove: longest tenure first (they've served, give others a turn)
        let mut by_tenure: Vec<(usize, usize)> = self.members.iter()
            .enumerate()
            .map(|(i, m)| (i, m.tenure))
            .collect();
        by_tenure.sort_by(|a, b| b.1.cmp(&a.1));

        let mut to_remove: Vec<usize> = by_tenure.iter()
            .take(n_rotate)
            .map(|&(i, _)| i)
            .collect();
        to_remove.sort_unstable_by(|a, b| b.cmp(a)); // remove from back first

        for idx in to_remove {
            let removed = self.members.remove(idx).unwrap();
            self.member_set.remove(&removed.node_id);
        }

        // Admit: trust-weighted selection from eligible non-members
        let mut candidates: Vec<(u64, f64)> = trust.iter()
            .filter(|&(&id, &t)| !self.member_set.contains(&id) && t >= self.config.min_trust)
            .map(|(&id, &t)| (id, t))
            .collect();

        // Deterministic shuffle using seed (simple LCG-based)
        let mut rng_state = seed;
        for i in (1..candidates.len()).rev() {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng_state >> 33) as usize % (i + 1);
            candidates.swap(i, j);
        }

        // Sort by trust descending after shuffle (trust-weighted: high trust preferred)
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Admit up to target size
        let n_admit = self.config.target_size.saturating_sub(self.members.len());
        for &(id, trust) in candidates.iter().take(n_admit) {
            self.members.push_back(Member { node_id: id, trust, tenure: 0 });
            self.member_set.insert(id);
        }

        // Adapt size: if network is small, committee might be smaller than target
        // That's fine — security scales with committee size.
    }

    /// Current committee members.
    pub fn members(&self) -> Vec<u64> {
        self.members.iter().map(|m| m.node_id).collect()
    }

    /// Committee size.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Check if a node is on the committee.
    pub fn is_member(&self, node_id: u64) -> bool {
        self.member_set.contains(&node_id)
    }

    /// Signing threshold for current committee.
    pub fn threshold(&self) -> usize {
        2 * self.size() / 3 + 1
    }

    /// Polynomial degree for current committee.
    pub fn degree(&self) -> usize {
        self.threshold() - 1
    }

    /// Signature budget for current epoch.
    pub fn signature_budget(&self) -> usize {
        self.degree() / 2
    }

    /// Average trust of committee members.
    pub fn average_trust(&self) -> f64 {
        if self.members.is_empty() { return 0.0; }
        self.members.iter().map(|m| m.trust).sum::<f64>() / self.members.len() as f64
    }

    /// Total trust of committee members.
    pub fn total_trust(&self) -> f64 {
        self.members.iter().map(|m| m.trust).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trust(n: usize) -> HashMap<u64, f64> {
        (0..n as u64).map(|i| (i, 1.0 / n as f64)).collect()
    }

    #[test]
    fn test_initialize() {
        let config = CommitteeConfig { target_size: 5, ..Default::default() };
        let mut committee = Committee::new(config);
        let trust = make_trust(20);
        committee.initialize(&trust);
        assert_eq!(committee.size(), 5);
        assert_eq!(committee.epoch, 0);
    }

    #[test]
    fn test_rotation_preserves_size() {
        let config = CommitteeConfig {
            target_size: 10,
            rotation_rate: 0.2, // rotate 2 of 10
            ..Default::default()
        };
        let mut committee = Committee::new(config);
        let trust = make_trust(50);
        committee.initialize(&trust);
        assert_eq!(committee.size(), 10);

        for epoch in 1..=20 {
            committee.rotate(&trust, epoch);
            assert_eq!(committee.size(), 10, "size changed at epoch {epoch}");
            assert_eq!(committee.epoch, epoch);
        }
    }

    #[test]
    fn test_rotation_changes_members() {
        let config = CommitteeConfig {
            target_size: 5,
            rotation_rate: 0.4, // rotate 2 of 5
            ..Default::default()
        };
        let mut committee = Committee::new(config);
        let trust = make_trust(20);
        committee.initialize(&trust);

        let initial = committee.members();

        // After several rotations, committee should be different
        for epoch in 1..=10 {
            committee.rotate(&trust, epoch);
        }
        let after = committee.members();

        // Not all the same (with 20 candidates and 40% rotation over 10 epochs)
        assert_ne!(initial, after, "committee didn't change after 10 rotations");
    }

    #[test]
    fn test_rolling_not_total_swap() {
        let config = CommitteeConfig {
            target_size: 10,
            rotation_rate: 0.1, // rotate 1 of 10
            ..Default::default()
        };
        let mut committee = Committee::new(config);
        let trust = make_trust(50);
        committee.initialize(&trust);

        let before = committee.members();
        committee.rotate(&trust, 1);
        let after = committee.members();

        // At most 1 member changed (10% of 10)
        let overlap: usize = before.iter()
            .filter(|id| after.contains(id))
            .count();
        assert!(overlap >= 9, "too many members changed: {overlap} overlap out of 10");
    }

    #[test]
    fn test_threshold_and_budget() {
        let config = CommitteeConfig { target_size: 100, ..Default::default() };
        let mut committee = Committee::new(config);
        let trust = make_trust(200);
        committee.initialize(&trust);

        assert_eq!(committee.threshold(), 67);
        assert_eq!(committee.degree(), 66);
        assert_eq!(committee.signature_budget(), 33);
    }

    #[test]
    fn test_dynamic_sizing() {
        // Small network: committee can't reach target size
        let config = CommitteeConfig { target_size: 100, ..Default::default() };
        let mut committee = Committee::new(config);
        let trust = make_trust(7); // only 7 nodes
        committee.initialize(&trust);

        // Committee should be 7 (all eligible), not 100
        assert_eq!(committee.size(), 7);
        assert_eq!(committee.threshold(), 5); // 2*7/3 + 1
    }

    #[test]
    fn test_trust_weighted_selection() {
        // One node has much higher trust — should be selected
        let mut trust = HashMap::new();
        trust.insert(1, 0.001);
        trust.insert(2, 0.001);
        trust.insert(3, 0.9); // high trust
        trust.insert(4, 0.001);
        trust.insert(5, 0.001);

        let config = CommitteeConfig { target_size: 3, ..Default::default() };
        let mut committee = Committee::new(config);
        committee.initialize(&trust);

        // Node 3 should always be in the committee (highest trust)
        assert!(committee.is_member(3), "high-trust node not selected");
    }
}
