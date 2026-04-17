//! # Personalized PageRank Trust Computation
//!
//! Each node computes trust from its own position in the Liu channel
//! graph via personalized PageRank (random walk with restart).
//! Sybil resistance: attack trust bounded by attack edges.
//!
//! ITS property: proved in Lean (SybilResistance.lean).

use std::collections::HashMap;

/// Damping factor (standard PageRank).
pub const DEFAULT_DAMPING: f64 = 0.85;

/// Number of power iterations.
pub const DEFAULT_ITERATIONS: usize = 20;

/// A directed weighted graph for trust computation.
pub struct TrustGraph {
    /// Adjacency: node → [(neighbor, weight)].
    edges: HashMap<u64, Vec<(u64, f64)>>,
    /// All node IDs.
    nodes: Vec<u64>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            nodes: Vec::new(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, id: u64) {
        if !self.nodes.contains(&id) {
            self.nodes.push(id);
            self.edges.entry(id).or_insert_with(Vec::new);
        }
    }

    /// Add a bidirectional edge (Liu channel between two nodes).
    pub fn add_channel(&mut self, a: u64, b: u64, weight: f64) {
        self.add_node(a);
        self.add_node(b);
        self.edges.entry(a).or_default().push((b, weight));
        self.edges.entry(b).or_default().push((a, weight));
    }

    /// Out-weight of a node (sum of edge weights).
    pub fn out_weight(&self, node: u64) -> f64 {
        self.edges.get(&node)
            .map(|neighbors| neighbors.iter().map(|(_, w)| w).sum())
            .unwrap_or(0.0)
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Compute personalized PageRank from a seed node.
    pub fn personalized_pagerank(&self, seed: u64, damping: f64, iterations: usize) -> HashMap<u64, f64> {
        let mut trust: HashMap<u64, f64> = self.nodes.iter().map(|&n| (n, 0.0)).collect();
        *trust.get_mut(&seed).unwrap() = 1.0;

        for _ in 0..iterations {
            let mut new_trust: HashMap<u64, f64> = self.nodes.iter().map(|&n| (n, 0.0)).collect();

            for &u in &self.nodes {
                let out_w = self.out_weight(u);
                if out_w == 0.0 { continue; }

                if let Some(neighbors) = self.edges.get(&u) {
                    for &(v, w) in neighbors {
                        *new_trust.get_mut(&v).unwrap() += damping * trust[&u] * w / out_w;
                    }
                }
            }

            // Teleport back to seed
            for &n in &self.nodes {
                let teleport = if n == seed { 1.0 - damping } else { 0.0 };
                *new_trust.get_mut(&n).unwrap() += teleport;
            }

            trust = new_trust;
        }

        trust
    }

    /// Compute personalized PageRank for **every** seed in `seeds`,
    /// then average the results. Useful for a single trust root that
    /// spreads damping across multiple known parties.
    pub fn averaged_pagerank(
        &self,
        seeds: &[u64],
        damping: f64,
        iterations: usize,
    ) -> HashMap<u64, f64> {
        let mut acc: HashMap<u64, f64> =
            self.nodes.iter().map(|&n| (n, 0.0)).collect();
        if seeds.is_empty() {
            return acc;
        }
        for &s in seeds {
            let r = self.personalized_pagerank(s, damping, iterations);
            for (k, v) in r {
                *acc.entry(k).or_insert(0.0) += v;
            }
        }
        let n = seeds.len() as f64;
        for v in acc.values_mut() {
            *v /= n;
        }
        acc
    }

    /// **Federated** trust: given K *independent* seed sets
    /// (e.g. Ethereum Foundation, Signal Foundation, EFF), compute
    /// the averaged PageRank under each set separately, then combine
    /// by taking the **minimum** across sets.
    ///
    /// Why minimum: a node is trusted only if *every* independent
    /// seed set reaches it. Capturing any single seed set doesn't
    /// grant trust — the attacker must corrupt all K simultaneously.
    ///
    /// `seed_sets` must be non-empty; empty input returns all-zeros.
    pub fn federated_pagerank(
        &self,
        seed_sets: &[&[u64]],
        damping: f64,
        iterations: usize,
    ) -> HashMap<u64, f64> {
        if seed_sets.is_empty() {
            return self.nodes.iter().map(|&n| (n, 0.0)).collect();
        }
        let per_set: Vec<HashMap<u64, f64>> = seed_sets
            .iter()
            .map(|s| self.averaged_pagerank(s, damping, iterations))
            .collect();
        let mut out: HashMap<u64, f64> =
            self.nodes.iter().map(|&n| (n, f64::INFINITY)).collect();
        for set_scores in &per_set {
            for &n in &self.nodes {
                let v = set_scores.get(&n).copied().unwrap_or(0.0);
                let cur = out.get_mut(&n).unwrap();
                if v < *cur {
                    *cur = v;
                }
            }
        }
        // Replace any INFINITY (no seed set ever saw this node) with 0.
        for v in out.values_mut() {
            if !v.is_finite() {
                *v = 0.0;
            }
        }
        out
    }

    /// Compute trust and check if honest majority holds.
    /// Returns (honest_trust, sybil_trust).
    pub fn check_honest_majority(
        &self,
        seed: u64,
        honest_nodes: &[u64],
        damping: f64,
        iterations: usize,
    ) -> (f64, f64) {
        let trust = self.personalized_pagerank(seed, damping, iterations);
        let honest_trust: f64 = honest_nodes.iter()
            .filter_map(|n| trust.get(n))
            .sum();
        let total: f64 = trust.values().sum();
        (honest_trust, total - honest_trust)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_graph() {
        let mut g = TrustGraph::new();
        g.add_channel(1, 2, 1.0);
        g.add_channel(2, 3, 1.0);
        g.add_channel(3, 1, 1.0);

        assert_eq!(g.node_count(), 3);

        let trust = g.personalized_pagerank(1, 0.85, 20);
        // Seed should have highest trust
        assert!(trust[&1] > trust[&2]);
        assert!(trust[&1] > trust[&3]);
        // Total trust ≈ 1
        let total: f64 = trust.values().sum();
        assert!((total - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_sybil_resistance() {
        // Honest clique: nodes 1-5, fully connected
        let mut g = TrustGraph::new();
        for i in 1..=5 {
            for j in (i+1)..=5 {
                g.add_channel(i, j, 1.0);
            }
        }
        // One attack edge: node 5 → sybil node 100
        g.add_channel(5, 100, 1.0);
        // Sybil creates 10 fake nodes connected to 100
        for s in 101..=110 {
            g.add_channel(100, s, 1.0);
        }

        let trust = g.personalized_pagerank(1, 0.85, 20);

        // Sybil region total trust should be small
        let sybil_trust: f64 = (100..=110).map(|s| trust.get(&s).copied().unwrap_or(0.0)).sum();
        let honest_trust: f64 = (1..=5).map(|s| trust[&s]).sum();

        // With 1 attack edge and honest degree ~4: Sybil trust should be small
        assert!(sybil_trust < 0.33, "Sybil trust too high: {sybil_trust}");
        assert!(honest_trust > 0.66, "Honest trust too low: {honest_trust}");
    }

    #[test]
    fn federated_minimum_across_seed_sets() {
        // Two disconnected components. Seed 1 lives in one; seed 10 in
        // the other. Node 99 is reachable only from seed 1's component.
        // So PageRank(99 | seed=10) must be 0.
        let mut g = TrustGraph::new();
        // Component A: 1 — 5 — 99
        g.add_channel(1, 5, 1.0);
        g.add_channel(5, 99, 1.0);
        // Component B: 10 — 20 (standalone, no connection to A)
        g.add_channel(10, 20, 1.0);

        // Must add the isolated nodes explicitly so they appear in the
        // node set used for the PageRank initial distribution.
        g.add_node(99);

        let set_a: &[u64] = &[1];
        let set_b: &[u64] = &[10];
        let fed = g.federated_pagerank(&[set_a, set_b], 0.85, 40);

        // Node 99 is unreachable from seed 10's component. PageRank(99
        // | seed=10) = 0, so federated min = 0.
        let t99 = *fed.get(&99).unwrap_or(&0.0);
        assert_eq!(t99, 0.0, "node 99 unreachable from set-b → zero fed trust");

        // Node 5 is reachable from seed 1 but NOT from seed 10 → fed = 0.
        let t5 = *fed.get(&5).unwrap();
        assert_eq!(t5, 0.0, "node 5 unreachable from set-b → zero fed trust");

        // Seeds themselves: seed 1 has nonzero PR under set-a, zero under
        // set-b (and vice versa) → both get fed = 0. The *purpose* of
        // federated is that NO node earns trust unless all seed sets
        // reach it. In this disjoint graph, nothing is globally trusted.
        let t1 = *fed.get(&1).unwrap();
        let t10 = *fed.get(&10).unwrap();
        assert_eq!(t1, 0.0);
        assert_eq!(t10, 0.0);
    }

    #[test]
    fn federated_single_set_equals_averaged() {
        // With a single seed set the federated computation equals the
        // averaged PageRank.
        let mut g = TrustGraph::new();
        g.add_channel(1, 2, 1.0);
        g.add_channel(2, 3, 1.0);
        let seeds: &[u64] = &[1];

        let avg = g.averaged_pagerank(seeds, 0.85, 30);
        let fed = g.federated_pagerank(&[seeds], 0.85, 30);

        for n in [1u64, 2, 3] {
            let a = *avg.get(&n).unwrap_or(&0.0);
            let f = *fed.get(&n).unwrap_or(&0.0);
            assert!((a - f).abs() < 1e-9, "node {n}: avg {a} vs fed {f}");
        }
    }
}
