//! # Idle-time pool pre-warming
//!
//! Policy primitive that decides **which** peer pools to refill
//! **when** the node has spare capacity. Decoupled from the actual
//! refill mechanism (Liu channels over TCP) so we can unit-test the
//! policy without spinning up networking.
//!
//! ## Inputs
//!
//! * Per-peer recent traffic counters (bytes observed in the current
//!   window). Pushed by the application via `record_activity()`.
//! * Per-peer current pool level in bytes.
//! * Target high-water mark in bytes (per-peer).
//! * Idle-trigger: the application calls `pick_refill_candidates()`
//!   whenever it's below some CPU/network threshold.
//!
//! ## Output
//!
//! An ordered list of peers to refill, top-K by recent traffic
//! filtered to those below the high-water mark. The list is ordered
//! so the "most-needed" peer comes first — caller can stop pre-warming
//! whenever it runs out of idle cycles.

use crate::identity::NodeId;
use std::collections::HashMap;

/// Tracker for per-peer recent traffic (byte counter over a rolling
/// window) and pool level. Decides who to pre-warm next.
///
/// Not thread-safe by itself. Wrap in `Arc<Mutex<..>>` in multi-
/// threaded contexts.
pub struct PrewarmTracker {
    /// Bytes observed per peer since the last `decay()` call.
    traffic: HashMap<NodeId, u64>,
    /// Current pool level per peer (bytes available).
    pool_level: HashMap<NodeId, usize>,
    /// Target high-water mark for each peer's pool. Below this,
    /// the peer is a refill candidate.
    high_water_bytes: usize,
    /// Exponential decay factor on traffic counters (applied each
    /// call to `decay()`). 1.0 = no decay; 0.5 = halve each period.
    decay_factor: f64,
}

impl PrewarmTracker {
    pub fn new(high_water_bytes: usize) -> Self {
        Self {
            traffic: HashMap::new(),
            pool_level: HashMap::new(),
            high_water_bytes,
            decay_factor: 0.9,
        }
    }

    pub fn with_decay(mut self, decay_factor: f64) -> Self {
        self.decay_factor = decay_factor;
        self
    }

    /// Record `bytes` of traffic observed with `peer`.
    pub fn record_activity(&mut self, peer: NodeId, bytes: u64) {
        *self.traffic.entry(peer).or_insert(0) += bytes;
    }

    /// Update the tracker's view of a peer's pool level.
    pub fn update_pool_level(&mut self, peer: NodeId, level_bytes: usize) {
        self.pool_level.insert(peer, level_bytes);
    }

    /// Forget a peer entirely (e.g. they've been evicted from DHT).
    pub fn drop_peer(&mut self, peer: &NodeId) {
        self.traffic.remove(peer);
        self.pool_level.remove(peer);
    }

    /// Apply exponential decay to all traffic counters. Call
    /// periodically (e.g. once per minute) so the "top-K" tracks
    /// recent activity, not all-time.
    pub fn decay(&mut self) {
        if self.decay_factor >= 1.0 {
            return;
        }
        for v in self.traffic.values_mut() {
            *v = (*v as f64 * self.decay_factor) as u64;
        }
        // Drop peers whose counter has decayed to zero to keep the
        // map bounded.
        self.traffic.retain(|_, v| *v > 0);
    }

    /// Top-K peers to pre-warm, ordered most-needed first.
    ///
    /// Selection criteria:
    ///   1. Pool level < `high_water_bytes` (otherwise already topped off).
    ///   2. Ranked by recent traffic descending (busiest peers first).
    ///   3. Ties broken by smaller pool level first (more depleted).
    ///   4. NodeId bytes as a final deterministic tiebreaker.
    pub fn pick_refill_candidates(&self, k: usize) -> Vec<NodeId> {
        let mut candidates: Vec<(u64, usize, NodeId)> = self
            .traffic
            .iter()
            .filter_map(|(&id, &traffic)| {
                let level = self.pool_level.get(&id).copied().unwrap_or(0);
                if level < self.high_water_bytes {
                    Some((traffic, level, id))
                } else {
                    None
                }
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.0.cmp(&a.0) // traffic DESC
                .then(a.1.cmp(&b.1)) // pool level ASC
                .then(a.2.cmp(&b.2)) // NodeId ASC (deterministic)
        });
        candidates.into_iter().take(k).map(|(_, _, id)| id).collect()
    }

    pub fn known_peers(&self) -> usize {
        self.traffic.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId::from_bytes([b; 48])
    }

    #[test]
    fn empty_tracker_returns_empty_candidates() {
        let t = PrewarmTracker::new(1024);
        assert!(t.pick_refill_candidates(5).is_empty());
    }

    #[test]
    fn busiest_peer_first() {
        let mut t = PrewarmTracker::new(1024);
        t.record_activity(id(1), 100);
        t.record_activity(id(2), 500);
        t.record_activity(id(3), 250);
        // No pool levels recorded → defaults to 0 → all below high water.
        let top = t.pick_refill_candidates(3);
        assert_eq!(top, vec![id(2), id(3), id(1)]);
    }

    #[test]
    fn peers_above_high_water_excluded() {
        let mut t = PrewarmTracker::new(1024);
        t.record_activity(id(1), 1000);
        t.record_activity(id(2), 500);
        t.update_pool_level(id(1), 2000); // above → skip
        t.update_pool_level(id(2), 100);  // below
        assert_eq!(t.pick_refill_candidates(10), vec![id(2)]);
    }

    #[test]
    fn tied_traffic_tiebreaks_by_depletion() {
        let mut t = PrewarmTracker::new(1024);
        t.record_activity(id(1), 500);
        t.record_activity(id(2), 500);
        t.update_pool_level(id(1), 800);  // less depleted
        t.update_pool_level(id(2), 200);  // more depleted → first
        assert_eq!(t.pick_refill_candidates(2), vec![id(2), id(1)]);
    }

    #[test]
    fn decay_eventually_drops_idle_peers() {
        let mut t = PrewarmTracker::new(1024).with_decay(0.5);
        t.record_activity(id(1), 1_000_000);
        t.record_activity(id(2), 2);
        // After two decays id(2) hits zero and gets dropped; id(1) is
        // still well above zero.
        t.decay();
        t.decay();
        assert_eq!(t.known_peers(), 1);
        let top = t.pick_refill_candidates(10);
        assert_eq!(top, vec![id(1)]);
    }

    #[test]
    fn drop_peer_removes_from_traffic_and_level() {
        let mut t = PrewarmTracker::new(1024);
        t.record_activity(id(9), 42);
        t.update_pool_level(id(9), 100);
        t.drop_peer(&id(9));
        assert!(t.pick_refill_candidates(10).is_empty());
    }

    #[test]
    fn top_k_truncates() {
        let mut t = PrewarmTracker::new(1024);
        for i in 1..=10 {
            t.record_activity(id(i), i as u64 * 100);
        }
        assert_eq!(t.pick_refill_candidates(3).len(), 3);
        assert_eq!(t.pick_refill_candidates(100).len(), 10);
    }
}
