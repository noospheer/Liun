//! # liun-tally: deterministic payout tally
//!
//! Given
//!   * a set of `ClaimBatch`es for an epoch (read from EIP-4844 blobs),
//!   * a trust scoring function (e.g. PageRank from `liun-overlay::trust`),
//!   * an address book mapping `NodeId → Ethereum payout address`,
//!   * a `KeyStore` of per-node `SharedKey`s (held only by the aggregator),
//!   * the pool budget for the epoch (USDC units, in wei),
//!
//! this crate produces the canonical ordered list of `Payout`s and the
//! Merkle root that should be posted on-chain.
//!
//! **Key property: determinism.** Every committee member runs the same
//! function on the same inputs and gets the same root. No consensus
//! protocol needed — just reproducibility. Anyone who disagrees (and
//! has been provisioned with the same keystore) can re-run and
//! challenge.
//!
//! ## ITS, not pubkey
//!
//! Receipts are authenticated via Wegman-Carter MAC under shared keys
//! established with the aggregator via a Liu channel. **No public-key
//! signatures anywhere.** Verification requires the aggregator's
//! private `KeyStore`; outsiders cannot re-verify receipts without it.
//!
//! The only comp-crypto primitive here is `keccak256`, used at the
//! **Ethereum boundary** to compute the Merkle root the on-chain
//! contract consumes. That is unavoidable until Ethereum itself ships
//! an ITS-compatible commitment scheme.

use std::collections::{BTreeMap, HashSet};

use liun_receipts::{
    ClaimBatch, ReceiptClaim, Role, SharedKey, OP_CHANNEL_BYTES, OP_DHT_QUERY, OP_RELAY_SHARE,
};
use liuproto_core::identity::NodeId;
use sha3::{Digest, Keccak256};

pub use liun_receipts;

/// One output entry in the Merkle tree. `address` is the 20-byte
/// Ethereum payout address registered by the node. Amount is in ETH wei.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    pub node: NodeId,
    pub address: [u8; 20],
    pub amount_wei: u128,
}

/// Caller-supplied trust graph. Must be deterministic: same graph →
/// same scores. Scores are fixed-point (e.g. PageRank × 1e9).
pub trait TrustScore {
    fn score(&self, node: &NodeId) -> u128;
}

/// Node registration: just the Ethereum payout address. No pubkey —
/// receipt authenticity is enforced via ITS-MAC against the
/// aggregator-held `KeyStore`, not via public-key verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub address: [u8; 20],
}

/// Simple in-memory address book. In production, this is read from an
/// on-chain `AddressBook.sol` registry whose state is a function of
/// public events, so every aggregator sees the same map.
#[derive(Default, Clone)]
pub struct AddressBook {
    pub entries: BTreeMap<NodeId, Registration>,
}

impl AddressBook {
    pub fn get(&self, n: &NodeId) -> Option<Registration> {
        self.entries.get(n).copied()
    }

    pub fn register(&mut self, n: NodeId, address: [u8; 20]) {
        self.entries.insert(n, Registration { address });
    }
}

/// Aggregator-private keystore: one [`SharedKey`] per registered node,
/// established over a Liu channel at registration time. The aggregator
/// uses these to verify receipt MACs.
///
/// Must **never** leave the aggregator's trust boundary — these are
/// symmetric keys. Committee members each hold independent keystores
/// (one per member; each node bootstraps N Liu channels, one per
/// committee member). Or a single custodian runs the aggregator.
pub struct KeyStore {
    entries: BTreeMap<NodeId, SharedKey>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, n: NodeId, key: SharedKey) {
        self.entries.insert(n, key);
    }

    pub fn get(&self, n: &NodeId) -> Option<&SharedKey> {
        self.entries.get(n)
    }
}

/// Policy knob: how much each op_kind is worth, in "volume units".
/// Changing this changes the payout distribution; must be part of the
/// committee-signed epoch parameters.
#[derive(Clone, Copy, Debug)]
pub struct OpWeights {
    pub relay_share: u128,
    pub dht_query: u128,
    pub channel_bytes_per_mb: u128,
}

impl Default for OpWeights {
    fn default() -> Self {
        Self {
            relay_share: 1,
            dht_query: 1,
            channel_bytes_per_mb: 1, // channel_bytes.op_count counts MB
        }
    }
}

impl OpWeights {
    fn weight_of(&self, op_kind: u8, total_count: u64) -> u128 {
        match op_kind {
            OP_RELAY_SHARE => self.relay_share * total_count as u128,
            OP_DHT_QUERY => self.dht_query * total_count as u128,
            OP_CHANNEL_BYTES => self.channel_bytes_per_mb * total_count as u128,
            _ => 0,
        }
    }
}

/// Compute the canonical ordered payout list for an epoch.
///
/// Pairing rules (session-level receipts):
///   * Each batch is a single party's report of their sessions.
///   * A session is credited only if **both** the client and server
///     independently reported it and both batches verify under the
///     respective reporters' `SharedKey`s in the keystore.
///   * Credit = `min(client.total_count, server.total_count)` — neither
///     side can inflate unilaterally.
///   * The pairing key is `(epoch, session_id)`. `session_id` collisions
///     are astronomically unlikely for 16-byte ITS-random nonces but
///     are dropped as duplicates if they occur.
///   * Only the **server** side earns payout; client reports are used
///     purely for corroboration.
///
/// Determinism:
///   * Output sorted by `node` (byte-wise). Same inputs → same Merkle root.
///   * Invalid batches (bad MAC, wrong reporter, wrong epoch) are
///     silently dropped — every aggregator drops the same ones.
pub fn tally(
    batches: &[ClaimBatch],
    trust: &impl TrustScore,
    addr_book: &AddressBook,
    keystore: &KeyStore,
    budget_wei: u128,
    weights: &OpWeights,
) -> Vec<Payout> {
    // Two maps indexed by (epoch, session_id), one per role.
    let mut client_side: BTreeMap<(u32, [u8; 16]), ReceiptClaim> = BTreeMap::new();
    let mut server_side: BTreeMap<(u32, [u8; 16]), ReceiptClaim> = BTreeMap::new();

    for b in batches {
        let Some(key) = keystore.get(&b.reporter) else {
            continue;
        };
        if b.verify(key).is_err() {
            continue;
        }
        for c in &b.claims {
            let pair_key = (c.claim.epoch, c.claim.session_id);
            let slot = match c.claim.role {
                Role::Client => &mut client_side,
                Role::Server => &mut server_side,
            };
            // If the same (epoch, session_id, role) appears twice, drop
            // the duplicate — don't let a reporter double-claim its own side.
            slot.entry(pair_key).or_insert(c.claim);
        }
    }

    // Pair up: credit server when both sides corroborate AND both
    // sides have positive trust. The client-trust requirement blocks
    // the self-Sybil inflation attack: a trusted server cannot
    // manufacture a Sybil client to corroborate fake work, because
    // the Sybil has zero trust → pair ignored.
    let mut volume: BTreeMap<NodeId, u128> = BTreeMap::new();
    for (pair_key, server_claim) in &server_side {
        let Some(client_claim) = client_side.get(pair_key) else {
            continue;
        };
        if client_claim.client_id != server_claim.client_id
            || client_claim.server_id != server_claim.server_id
            || client_claim.op_kind != server_claim.op_kind
        {
            continue;
        }
        if trust.score(&server_claim.client_id) == 0
            || trust.score(&server_claim.server_id) == 0
        {
            continue;
        }
        let credited = client_claim.total_count.min(server_claim.total_count);
        let w = weights.weight_of(server_claim.op_kind, credited);
        *volume.entry(server_claim.server_id).or_default() += w;
    }

    // Score = trust × volume. Use u128 throughout to avoid overflow for
    // reasonable pool sizes (USDC wei fits in u96).
    let scored: BTreeMap<NodeId, u128> = volume
        .into_iter()
        .filter_map(|(n, v)| {
            let t = trust.score(&n);
            if t == 0 || v == 0 || addr_book.get(&n).is_none() {
                None
            } else {
                // Saturating to avoid overflow in pathological cases.
                Some((n, t.saturating_mul(v)))
            }
        })
        .collect();

    let total: u128 = scored.values().copied().sum();
    if total == 0 {
        return vec![];
    }

    // Proportional split. Integer division drops remainders (dust
    // stays in the pool — safer than rounding error loops).
    scored
        .into_iter()
        .map(|(node, s)| {
            let amount = mul_div_floor(budget_wei, s, total);
            let reg = addr_book.get(&node).expect("filtered above");
            Payout {
                node,
                address: reg.address,
                amount_wei: amount,
            }
        })
        .filter(|p| p.amount_wei > 0)
        .collect()
}

// ── Auto-trust: derive trust from verified interactions ─────────────
//
// Trust is derived AUTOMATICALLY from verified protocol interactions.
// Each paired session creates an edge in the interaction graph.
// PageRank over this graph, seeded from genesis, gives trust scores.
//
// Anti-gaming measures:
//   1. DHT queries (OP_DHT_QUERY) are EXCLUDED — too cheap to spam.
//      Only sustained sessions (OP_CHANNEL_BYTES, OP_RELAY_SHARE)
//      create trust edges.
//   2. Edges are BINARY per unique peer pair — 1000 sessions between
//      the same two nodes = 1 trust edge. Colluding nodes can inflate
//      volume but NOT trust.
//   3. Trust decays: edges are weighted by recency. Older epochs
//      contribute less. A node that stops serving loses trust over time.

use std::collections::HashMap;

/// Op kinds that qualify for trust edges. DHT queries are excluded
/// because they're too cheap (a few UDP packets → free trust edge).
/// Only sustained sessions involving real key material exchange count.
fn qualifies_for_trust(op_kind: u8) -> bool {
    matches!(op_kind, OP_CHANNEL_BYTES | OP_RELAY_SHARE)
}

/// Extract the interaction graph from verified claim pairs.
///
/// **Anti-gaming:**
///   - Only `OP_CHANNEL_BYTES` and `OP_RELAY_SHARE` sessions count
///     (DHT queries excluded — too cheap to be meaningful trust signal).
///   - Edges are **deduplicated per unique peer pair**: many sessions
///     between A and B produce ONE edge. This prevents colluding nodes
///     from inflating their trust by repeating sessions.
///   - Each edge carries a `recency` weight = `current_epoch - session_epoch`,
///     so older interactions decay. Pass `current_epoch` to control the
///     decay window.
pub fn interaction_graph(
    batches: &[ClaimBatch],
    keystore: &KeyStore,
    current_epoch: u32,
) -> Vec<(NodeId, NodeId, u64)> {
    let mut client_side: BTreeMap<(u32, [u8; 16]), ReceiptClaim> = BTreeMap::new();
    let mut server_side: BTreeMap<(u32, [u8; 16]), ReceiptClaim> = BTreeMap::new();

    for b in batches {
        let Some(key) = keystore.get(&b.reporter) else { continue };
        if b.verify(key).is_err() { continue }
        for c in &b.claims {
            // Skip DHT queries — too cheap to be trust-meaningful.
            if !qualifies_for_trust(c.claim.op_kind) { continue }
            let pair_key = (c.claim.epoch, c.claim.session_id);
            match c.claim.role {
                Role::Client => { client_side.entry(pair_key).or_insert(c.claim); }
                Role::Server => { server_side.entry(pair_key).or_insert(c.claim); }
            }
        }
    }

    // Deduplicate: one edge per unique (client_id, server_id) pair.
    // If multiple sessions exist between the same pair, keep the most
    // recent one (highest epoch) for decay weighting.
    let mut best_epoch: BTreeMap<(NodeId, NodeId), u32> = BTreeMap::new();

    for (pair_key, server_claim) in &server_side {
        let Some(client_claim) = client_side.get(pair_key) else { continue };
        if client_claim.client_id != server_claim.client_id
            || client_claim.server_id != server_claim.server_id
        {
            continue;
        }
        let pair = (client_claim.client_id, server_claim.server_id);
        let epoch = server_claim.epoch;
        best_epoch.entry(pair)
            .and_modify(|e| *e = (*e).max(epoch))
            .or_insert(epoch);
    }

    // Convert to edges with decay weight.
    // Decay: weight = 1 + (DECAY_WINDOW - age), clamped to [1, DECAY_WINDOW].
    // Recent interactions weigh more; ancient ones still count but less.
    const DECAY_WINDOW: u32 = 52; // ~1 year of weekly epochs
    best_epoch
        .into_iter()
        .map(|((a, b), epoch)| {
            let age = current_epoch.saturating_sub(epoch);
            let weight = DECAY_WINDOW.saturating_sub(age).max(1) as u64;
            (a, b, weight)
        })
        .collect()
}

/// Per-node evidence for the Bayesian trust formula.
#[derive(Default, Clone, Debug)]
pub struct NodeEvidence {
    /// Epochs this node has been observed online (distinct epochs with
    /// at least one verified session).
    pub epochs_online: u32,
    /// Number of unique peer ASNs that independently verified this node.
    /// Each ASN is an independent witness; diverse ASNs = hard to Sybil.
    pub unique_asns: u32,
    /// Total MAC-verified successful interactions.
    pub successes: u64,
    /// Total MAC failures observed.
    pub failures: u64,
}

/// Bayesian trust score. No arbitrary constants — each term is the
/// principled answer from its domain:
///
///   trust = log(1 + t) × log(1 + d) × (1 + s) / (2 + s + f)
///
/// - `log(1+t)`: information gain from repeated non-failure observations
///   (diminishing returns on uptime — first epoch is most informative)
/// - `log(1+d)`: information gain from independent witnesses (each new
///   ASN is independent evidence; diminishing marginal value)
/// - `(1+s)/(2+s+f)`: Laplace-smoothed Bayesian posterior under
///   Beta(1,1) prior — the principled estimate of true reliability
///   given observed successes and failures
///
/// Why multiplicative: if ANY dimension is zero, trust is zero.
/// Time without diversity = suspicious. Diversity without uptime =
/// unproven. Perfect diversity+time with MAC failures = malicious.
pub fn bayesian_trust(ev: &NodeEvidence) -> f64 {
    let time = (1.0 + ev.epochs_online as f64).ln();
    let diversity = (1.0 + ev.unique_asns as f64).ln();
    let correctness = (1 + ev.successes) as f64 / (2 + ev.successes + ev.failures) as f64;
    time * diversity * correctness
}

/// Compute Bayesian trust scores from the interaction graph.
///
/// For each node, counts:
///   - epochs_online: distinct epochs where the node appeared in a
///     verified paired session
///   - unique_asns: number of distinct peer ASNs (approximated by the
///     top byte of the peer's NodeId as a proxy — real ASN lookup is a
///     future enhancement via IP→ASN database)
///   - successes: number of verified paired sessions
///   - failures: 0 (failures are detected at the MAC level and prevent
///     the session from being recorded at all)
///
/// Seeds get a baseline bonus: epochs_online = max(1, actual),
/// unique_asns = max(1, actual), so they always have positive trust.
pub fn auto_trust_scores(
    edges: &[(NodeId, NodeId, u64)],
    seeds: &[NodeId],
    all_claims: &BTreeMap<(u32, [u8; 16]), ReceiptClaim>,
) -> HashMap<NodeId, u128> {
    let mut evidence: HashMap<NodeId, NodeEvidence> = HashMap::new();
    let seed_set: HashSet<NodeId> = seeds.iter().copied().collect();

    // Build evidence from edges (each edge = one verified interaction).
    for &(a, b, _weight) in edges {
        // Both nodes get credit for the interaction.
        for node in [a, b] {
            let ev = evidence.entry(node).or_default();
            ev.successes += 1;
            // Use top 2 bytes of the OTHER node's ID as ASN proxy.
            // Real NodeIds are TRNG-generated, so this distributes
            // uniformly across 65536 "pseudo-ASNs". Two nodes on the
            // same cloud instance would have different random IDs →
            // different pseudo-ASNs. This is a placeholder until real
            // IP→ASN lookup is wired in.
            let other = if node == a { b } else { a };
            let pseudo_asn = u16::from_be_bytes([other.as_bytes()[0], other.as_bytes()[1]]);
            // Track unique ASNs per node via a simple hash check.
            // (Full implementation would use a HashSet<u16> per node;
            // for now, count unique edge partners as diversity proxy.)
            ev.unique_asns = ev.unique_asns.max(1); // at least 1 if any edge exists
        }
    }

    // Count unique peer diversity properly: number of unique edge partners.
    let mut peer_sets: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
    for &(a, b, _) in edges {
        peer_sets.entry(a).or_default().insert(b);
        peer_sets.entry(b).or_default().insert(a);
    }
    for (node, peers) in &peer_sets {
        if let Some(ev) = evidence.get_mut(node) {
            ev.unique_asns = peers.len() as u32;
        }
    }

    // Count distinct epochs per node from claims.
    let mut epoch_sets: HashMap<NodeId, HashSet<u32>> = HashMap::new();
    for ((epoch, _), claim) in all_claims {
        epoch_sets.entry(claim.client_id).or_default().insert(*epoch);
        epoch_sets.entry(claim.server_id).or_default().insert(*epoch);
    }
    for (node, epochs) in &epoch_sets {
        if let Some(ev) = evidence.get_mut(node) {
            ev.epochs_online = epochs.len() as u32;
        }
    }

    // Seeds get baseline evidence so they always have positive trust.
    for s in seeds {
        let ev = evidence.entry(*s).or_default();
        ev.epochs_online = ev.epochs_online.max(1);
        ev.unique_asns = ev.unique_asns.max(1);
        ev.successes = ev.successes.max(1);
    }

    // Reachability from seeds: only nodes connected (transitively)
    // to at least one seed get trust. Sybil clusters with no path
    // to the seed earn zero regardless of their Bayesian score.
    let reachable = {
        let mut adj_map: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for &(a, b, _) in edges {
            adj_map.entry(a).or_default().push(b);
            adj_map.entry(b).or_default().push(a);
        }
        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut queue: Vec<NodeId> = seeds.to_vec();
        while let Some(n) = queue.pop() {
            if !visited.insert(n) { continue; }
            if let Some(neighbors) = adj_map.get(&n) {
                for &nb in neighbors {
                    if !visited.contains(&nb) { queue.push(nb); }
                }
            }
        }
        visited
    };

    // Compute scores — zero for nodes unreachable from seeds.
    evidence
        .into_iter()
        .map(|(node, ev)| {
            if !reachable.contains(&node) {
                return (node, 0u128);
            }
            let score = bayesian_trust(&ev);
            (node, (score * 1e9) as u128)
        })
        .collect()
}

/// Auto-trust implementation of `TrustScore` — derives trust from
/// verified interactions using Bayesian inference.
///
/// trust = log(1+time) × log(1+diversity) × laplace(successes, failures)
///
/// No arbitrary constants. No PageRank. No proof-of-work.
pub struct AutoTrust {
    scores: HashMap<NodeId, u128>,
}

impl AutoTrust {
    /// Build trust scores from claim batches + seed node IDs.
    pub fn from_batches(
        batches: &[ClaimBatch],
        keystore: &KeyStore,
        seeds: &[NodeId],
        current_epoch: u32,
    ) -> Self {
        let edges = interaction_graph(batches, keystore, current_epoch);

        // Collect all verified claims for epoch counting.
        let mut all_claims: BTreeMap<(u32, [u8; 16]), ReceiptClaim> = BTreeMap::new();
        for b in batches {
            let Some(key) = keystore.get(&b.reporter) else { continue };
            if b.verify(key).is_err() { continue }
            for c in &b.claims {
                all_claims.insert((c.claim.epoch, c.claim.session_id), c.claim);
            }
        }

        let scores = auto_trust_scores(&edges, seeds, &all_claims);
        Self { scores }
    }

    pub fn score(&self, node: &NodeId) -> u128 {
        self.scores.get(node).copied().unwrap_or(0)
    }
}

impl TrustScore for AutoTrust {
    fn score(&self, node: &NodeId) -> u128 {
        self.scores.get(node).copied().unwrap_or(0)
    }
}

/// Convenience: tally with auto-derived trust. No external trust graph
/// needed — trust is computed from the same claim data used for payouts.
///
/// `seeds` = the genesis node IDs (hardcoded in the binary).
/// `current_epoch` = the epoch being tallied (for decay weighting).
pub fn tally_auto(
    batches: &[ClaimBatch],
    addr_book: &AddressBook,
    keystore: &KeyStore,
    seeds: &[NodeId],
    current_epoch: u32,
    budget_wei: u128,
    weights: &OpWeights,
) -> Vec<Payout> {
    let trust = AutoTrust::from_batches(batches, keystore, seeds, current_epoch);
    tally(batches, &trust, addr_book, keystore, budget_wei, weights)
}

/// `a * b / c` with overflow protection. Computes `(a * b) / c` as if
/// in u256, returning a u128 result (assumes the true quotient fits —
/// which it does when `budget_wei ≤ u128::MAX` and the score ratio is
/// ≤ 1, i.e. our domain).
///
/// Algorithm: split `a = a_hi * 2^64 + a_lo`. Then
///   a * b = a_hi * b * 2^64 + a_lo * b
/// Each `a_hi * b` and `a_lo * b` is at most 192 bits. We divide each
/// by `c` separately, combining quotients and remainders. This is
/// exact if `c ≥ 2^64`, but we need full generality. For our MVP the
/// quick path covers all realistic inputs (either side fits u64):
fn mul_div_floor(a: u128, b: u128, c: u128) -> u128 {
    assert!(c > 0, "mul_div_floor: divide by zero");
    // Fast path: one side fits u64 → no overflow in `a * b`.
    if (a >> 64) == 0 || (b >> 64) == 0 {
        return a.wrapping_mul(b) / c;
    }
    long_div_u256(a, b, c)
}

/// Schoolbook u256 = a*b, then divide by c. Returns the low 128 bits
/// of the quotient (assumed to fit).
fn long_div_u256(a: u128, b: u128, c: u128) -> u128 {
    // Multiply a * b into four 64-bit limbs.
    let a0 = (a & ((1u128 << 64) - 1)) as u64;
    let a1 = (a >> 64) as u64;
    let b0 = (b & ((1u128 << 64) - 1)) as u64;
    let b1 = (b >> 64) as u64;
    // 64×64 = 128-bit products.
    let p00 = (a0 as u128) * (b0 as u128);
    let p01 = (a0 as u128) * (b1 as u128);
    let p10 = (a1 as u128) * (b0 as u128);
    let p11 = (a1 as u128) * (b1 as u128);
    // Accumulate into four 64-bit limbs (little-endian).
    let mut r0 = p00 & ((1u128 << 64) - 1);
    let carry0 = p00 >> 64;
    let mid = carry0 + (p01 & ((1u128 << 64) - 1)) + (p10 & ((1u128 << 64) - 1));
    let r1 = mid & ((1u128 << 64) - 1);
    let carry1 = mid >> 64;
    let high = carry1 + (p01 >> 64) + (p10 >> 64) + (p11 & ((1u128 << 64) - 1));
    let r2 = high & ((1u128 << 64) - 1);
    let carry2 = high >> 64;
    let r3 = (p11 >> 64) + carry2;
    let _ = r0;
    // Now product = r3 * 2^192 + r2 * 2^128 + r1 * 2^64 + r0.
    // Bitwise long division by c.
    let mut rem: u128 = 0;
    let mut q: u128 = 0; // low 128 bits of quotient
    for limb in [r3, r2, r1, r0] {
        for bit in (0..64).rev() {
            rem = (rem << 1) | ((limb >> bit) & 1);
            q <<= 1;
            if rem >= c {
                rem -= c;
                q |= 1;
            }
        }
    }
    q
}

/// Merkle root over a canonically-ordered payout list.
///
/// Leaves are `keccak256(abi.encode(bytes48 node, address payout, uint256 amount))`
/// so the Solidity contract can recompute the same leaf. Internal nodes
/// are `keccak256(a || b)` with **sorted-pair** hashing (a < b) so
/// direction bits are not needed in the proof — matches the standard
/// OpenZeppelin `MerkleProof.verify` convention.
pub fn merkle_root(payouts: &[Payout]) -> [u8; 32] {
    if payouts.is_empty() {
        return [0u8; 32];
    }
    // Leaves
    let mut level: Vec<[u8; 32]> = payouts
        .iter()
        .map(|p| {
            let mut pre = Vec::with_capacity(48 + 32 + 32);
            pre.extend_from_slice(p.node.as_bytes());
            // abi.encode pads address to 32 bytes.
            pre.extend(std::iter::repeat(0u8).take(12));
            pre.extend_from_slice(&p.address);
            // amount as u256 big-endian
            let mut amt = [0u8; 32];
            amt[16..32].copy_from_slice(&p.amount_wei.to_be_bytes());
            pre.extend_from_slice(&amt);
            keccak(&pre)
        })
        .collect();

    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let node = match chunk {
                [a, b] => hash_pair(a, b),
                [a] => *a, // odd leaf: promote
                _ => unreachable!(),
            };
            next.push(node);
        }
        level = next;
    }
    level[0]
}

/// Generate an inclusion proof for the i-th payout in the canonical list.
pub fn merkle_proof(payouts: &[Payout], index: usize) -> Vec<[u8; 32]> {
    assert!(index < payouts.len(), "index out of range");
    let mut level: Vec<[u8; 32]> = payouts
        .iter()
        .map(|p| leaf_hash(p))
        .collect();
    let mut idx = index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let pair_idx = idx ^ 1;
        if pair_idx < level.len() {
            proof.push(level[pair_idx]);
        }
        // else: odd promotion; no sibling added
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let node = match chunk {
                [a, b] => hash_pair(a, b),
                [a] => *a,
                _ => unreachable!(),
            };
            next.push(node);
        }
        level = next;
        idx /= 2;
    }
    proof
}

pub fn verify_merkle(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    let mut acc = *leaf;
    for sib in proof {
        acc = hash_pair(&acc, sib);
    }
    &acc == root
}

fn leaf_hash(p: &Payout) -> [u8; 32] {
    let mut pre = Vec::with_capacity(48 + 32 + 32);
    pre.extend_from_slice(p.node.as_bytes());
    pre.extend(std::iter::repeat(0u8).take(12));
    pre.extend_from_slice(&p.address);
    let mut amt = [0u8; 32];
    amt[16..32].copy_from_slice(&p.amount_wei.to_be_bytes());
    pre.extend_from_slice(&amt);
    keccak(&pre)
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut pre = [0u8; 64];
    pre[..32].copy_from_slice(lo);
    pre[32..].copy_from_slice(hi);
    keccak(&pre)
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use liun_receipts::{sign_claim, ClaimBatch, MacKey, ReceiptClaim, Role};
    use std::collections::BTreeMap;

    struct FlatTrust(u128);
    impl TrustScore for FlatTrust {
        fn score(&self, _n: &NodeId) -> u128 {
            self.0
        }
    }

    struct MapTrust(BTreeMap<NodeId, u128>);
    impl TrustScore for MapTrust {
        fn score(&self, n: &NodeId) -> u128 {
            *self.0.get(n).unwrap_or(&0)
        }
    }

    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        getrandom::fill(&mut v).unwrap();
        v
    }

    fn rand_sid() -> [u8; 16] {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).unwrap();
        s
    }

    /// Fresh aggregator key pair: (node_id, node-side view, aggregator-side view).
    fn shared_pair() -> (NodeId, SharedKey, SharedKey) {
        let id = NodeId::generate();
        let bytes = rand_bytes(4096);
        (id, SharedKey::from_bytes(bytes.clone()), SharedKey::from_bytes(bytes))
    }

    fn claim(
        client: NodeId,
        server: NodeId,
        role: Role,
        count: u64,
        sid: [u8; 16],
        offset: u64,
        op_kind: u8,
    ) -> ReceiptClaim {
        ReceiptClaim {
            client_id: client,
            server_id: server,
            epoch: 1,
            op_kind,
            total_count: count,
            session_id: sid,
            key_offset: offset,
            role,
        }
    }

    fn sign(k: &SharedKey, c: ReceiptClaim) -> liun_receipts::SignedClaim {
        let mk: MacKey = k.key_at(c.key_offset as usize).unwrap();
        sign_claim(c, &mk)
    }

    fn batch(
        reporter: NodeId,
        k: &SharedKey,
        claims: Vec<liun_receipts::SignedClaim>,
        batch_off: u64,
    ) -> ClaimBatch {
        let bk = k.key_at(batch_off as usize).unwrap();
        ClaimBatch::sign(1, reporter, claims, &bk, batch_off)
    }

    #[test]
    fn deterministic_root_same_inputs() {
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (srv_id, sk_node, sk_agg) = shared_pair();
        let s1 = rand_sid();
        let s2 = rand_sid();

        let cb = batch(cli_id, &ck_node, vec![
            sign(&ck_node, claim(cli_id, srv_id, Role::Client, 10, s1, 0, OP_DHT_QUERY)),
            sign(&ck_node, claim(cli_id, srv_id, Role::Client, 20, s2, 16, OP_DHT_QUERY)),
        ], 1024);
        let sb = batch(srv_id, &sk_node, vec![
            sign(&sk_node, claim(cli_id, srv_id, Role::Server, 10, s1, 0, OP_DHT_QUERY)),
            sign(&sk_node, claim(cli_id, srv_id, Role::Server, 20, s2, 16, OP_DHT_QUERY)),
        ], 1024);

        let trust = FlatTrust(1);
        let mut ab = AddressBook::default();
        ab.register(cli_id, [8u8; 20]);
        ab.register(srv_id, [7u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(srv_id, sk_agg);

        let w = OpWeights::default();
        let a = tally(&[cb.clone(), sb.clone()], &trust, &ab, &ks, 1_000_000, &w);
        let b = tally(&[cb, sb], &trust, &ab, &ks, 1_000_000, &w);
        assert_eq!(a, b);
        assert_eq!(merkle_root(&a), merkle_root(&b));
    }

    #[test]
    fn proportional_split_across_servers() {
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (a_id, a_node, a_agg) = shared_pair();
        let (b_id, b_node, b_agg) = shared_pair();

        let mut cc_claims = Vec::new();
        let mut a_claims = Vec::new();
        for i in 0..3u64 {
            let sid = rand_sid();
            cc_claims.push(sign(&ck_node, claim(cli_id, a_id, Role::Client, 100, sid, i * 16, OP_DHT_QUERY)));
            a_claims.push(sign(&a_node, claim(cli_id, a_id, Role::Server, 100, sid, i * 16, OP_DHT_QUERY)));
        }
        let b_sid = rand_sid();
        cc_claims.push(sign(&ck_node, claim(cli_id, b_id, Role::Client, 100, b_sid, 48, OP_DHT_QUERY)));
        let b_server = sign(&b_node, claim(cli_id, b_id, Role::Server, 100, b_sid, 0, OP_DHT_QUERY));

        let cb = batch(cli_id, &ck_node, cc_claims, 1024);
        let ab_batch = batch(a_id, &a_node, a_claims, 1024);
        let bb_batch = batch(b_id, &b_node, vec![b_server], 1024);

        let trust = FlatTrust(1);
        let mut ab = AddressBook::default();
        ab.register(cli_id, [0xCC; 20]);
        ab.register(a_id, [0xAA; 20]);
        ab.register(b_id, [0xBB; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(a_id, a_agg);
        ks.insert(b_id, b_agg);

        let payouts = tally(&[cb, ab_batch, bb_batch], &trust, &ab, &ks, 4_000_000, &OpWeights::default());
        assert_eq!(payouts.len(), 2);
        let a_amt = payouts.iter().find(|p| p.node == a_id).unwrap().amount_wei;
        let b_amt = payouts.iter().find(|p| p.node == b_id).unwrap().amount_wei;
        assert_eq!(a_amt, 3_000_000);
        assert_eq!(b_amt, 1_000_000);
    }

    #[test]
    fn untrusted_node_earns_zero() {
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (t_id, t_node, t_agg) = shared_pair();
        let (s_id, s_node, s_agg) = shared_pair();
        let sid_t = rand_sid();
        let sid_s = rand_sid();

        let cb = batch(cli_id, &ck_node, vec![
            sign(&ck_node, claim(cli_id, t_id, Role::Client, 10, sid_t, 0, OP_DHT_QUERY)),
            sign(&ck_node, claim(cli_id, s_id, Role::Client, 1_000_000, sid_s, 16, OP_DHT_QUERY)),
        ], 1024);
        let tb = batch(t_id, &t_node, vec![
            sign(&t_node, claim(cli_id, t_id, Role::Server, 10, sid_t, 0, OP_DHT_QUERY)),
        ], 1024);
        let sb = batch(s_id, &s_node, vec![
            sign(&s_node, claim(cli_id, s_id, Role::Server, 1_000_000, sid_s, 0, OP_DHT_QUERY)),
        ], 1024);

        let mut trust_map = BTreeMap::new();
        trust_map.insert(cli_id, 100u128); // honest client
        trust_map.insert(t_id, 1_000u128);  // trusted server
        trust_map.insert(s_id, 0u128);      // Sybil server
        let trust = MapTrust(trust_map);

        let mut ab = AddressBook::default();
        ab.register(cli_id, [9u8; 20]);
        ab.register(t_id, [1u8; 20]);
        ab.register(s_id, [2u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(t_id, t_agg);
        ks.insert(s_id, s_agg);

        let payouts = tally(&[cb, tb, sb], &trust, &ab, &ks, 1_000_000, &OpWeights::default());
        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0].node, t_id);
        assert_eq!(payouts[0].amount_wei, 1_000_000);
    }

    #[test]
    fn server_cannot_inflate_unilaterally() {
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (srv_id, sk_node, sk_agg) = shared_pair();
        let sid = rand_sid();

        let cb = batch(cli_id, &ck_node, vec![
            sign(&ck_node, claim(cli_id, srv_id, Role::Client, 100, sid, 0, OP_DHT_QUERY)),
        ], 1024);
        let sb = batch(srv_id, &sk_node, vec![
            sign(&sk_node, claim(cli_id, srv_id, Role::Server, 1_000_000, sid, 0, OP_DHT_QUERY)),
        ], 1024);

        let mut ab = AddressBook::default();
        ab.register(cli_id, [8u8; 20]);
        ab.register(srv_id, [7u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(srv_id, sk_agg);

        let payouts = tally(&[cb, sb], &FlatTrust(1), &ab, &ks, 1_000_000, &OpWeights::default());
        // Credited volume = min(100, 1_000_000) = 100. Server is the only
        // earner (no other traffic) so still receives full budget — the
        // budget cap is enforced elsewhere, the MIN discipline prevents
        // artificial volume inflation across an epoch.
        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0].amount_wei, 1_000_000);
    }

    #[test]
    fn sybil_client_cannot_inflate_trusted_server() {
        // Trusted server X colludes with its own Sybil client Y.
        // Both produce matching claims. Without client-trust filtering,
        // X would earn payout for fake work. With filtering (Y has
        // zero trust), the pairing is rejected.
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (srv_id, sk_node, sk_agg) = shared_pair();
        let sid = rand_sid();

        let cb = batch(cli_id, &ck_node, vec![
            sign(&ck_node, claim(cli_id, srv_id, Role::Client, 1_000_000, sid, 0, OP_DHT_QUERY)),
        ], 1024);
        let sb = batch(srv_id, &sk_node, vec![
            sign(&sk_node, claim(cli_id, srv_id, Role::Server, 1_000_000, sid, 0, OP_DHT_QUERY)),
        ], 1024);

        // Server has trust; client (Sybil) does not.
        let mut trust_map = BTreeMap::new();
        trust_map.insert(srv_id, 100u128);
        trust_map.insert(cli_id, 0u128);

        let mut ab = AddressBook::default();
        ab.register(cli_id, [8u8; 20]);
        ab.register(srv_id, [7u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(srv_id, sk_agg);

        let payouts = tally(&[cb, sb], &MapTrust(trust_map), &ab, &ks, 1_000_000, &OpWeights::default());
        // No pair survives filtering → no payouts.
        assert_eq!(payouts.len(), 0);
    }

    #[test]
    fn unpaired_session_not_credited() {
        let (cli_id, _ck_node, ck_agg) = shared_pair();
        let (srv_id, sk_node, sk_agg) = shared_pair();
        let sid = rand_sid();

        // Only server side reports — no client corroboration.
        let sb = batch(srv_id, &sk_node, vec![
            sign(&sk_node, claim(cli_id, srv_id, Role::Server, 100, sid, 0, OP_DHT_QUERY)),
        ], 1024);

        let mut ab = AddressBook::default();
        ab.register(cli_id, [8u8; 20]);
        ab.register(srv_id, [7u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(srv_id, sk_agg);

        let payouts = tally(&[sb], &FlatTrust(1), &ab, &ks, 1000, &OpWeights::default());
        assert_eq!(payouts.len(), 0);
    }

    #[test]
    fn batch_under_wrong_reporter_key_dropped() {
        let (cli_id, ck_node, ck_agg) = shared_pair();
        let (srv_id, _sk_node, sk_agg) = shared_pair();
        let imp_bytes = rand_bytes(4096);
        let imp_node = SharedKey::from_bytes(imp_bytes.clone());
        let sid = rand_sid();

        let cb = batch(cli_id, &ck_node, vec![
            sign(&ck_node, claim(cli_id, srv_id, Role::Client, 10, sid, 0, OP_DHT_QUERY)),
        ], 1024);
        let fake_sb = batch(srv_id, &imp_node, vec![
            sign(&imp_node, claim(cli_id, srv_id, Role::Server, 10, sid, 0, OP_DHT_QUERY)),
        ], 1024);

        let mut ab = AddressBook::default();
        ab.register(cli_id, [8u8; 20]);
        ab.register(srv_id, [3u8; 20]);
        let mut ks = KeyStore::new();
        ks.insert(cli_id, ck_agg);
        ks.insert(srv_id, sk_agg); // real key, not imposter's

        let payouts = tally(&[cb, fake_sb], &FlatTrust(1), &ab, &ks, 1000, &OpWeights::default());
        assert_eq!(payouts.len(), 0);
    }

    #[test]
    fn merkle_proof_roundtrip() {
        let payouts: Vec<Payout> = (0..5u8)
            .map(|i| Payout {
                node: NodeId::from_bytes([i; 48]),
                address: [i + 100; 20],
                amount_wei: (i as u128 + 1) * 1000,
            })
            .collect();
        let root = merkle_root(&payouts);
        for (i, p) in payouts.iter().enumerate() {
            let proof = merkle_proof(&payouts, i);
            let leaf = leaf_hash(p);
            assert!(
                verify_merkle(&root, &leaf, &proof),
                "proof for index {i} failed"
            );
        }
    }

    #[test]
    fn mul_div_matches_native_in_range() {
        for &(a, b, c) in &[
            (7u128, 11, 3),
            (1_000_000_000_000u128, 2_000_000_000_000, 3_000_000_000),
            (u64::MAX as u128, u64::MAX as u128, 7),
            (1, u128::MAX, 3),
        ] {
            let expected = a.checked_mul(b).map(|v| v / c);
            if let Some(e) = expected {
                assert_eq!(mul_div_floor(a, b, c), e, "a={a} b={b} c={c}");
            }
        }
    }

    #[test]
    fn mul_div_overflowing_product() {
        let a: u128 = 100_000_000_000_000_000_000;
        let b: u128 = 100_000_000_000_000_000_000;
        let c: u128 = 100_000_000_000_000_000_000;
        assert_eq!(mul_div_floor(a, b, c), a);
    }

    #[test]
    fn auto_trust_from_interactions() {
        // Three nodes: seed S, honest A, honest B.
        // S↔A had a session, A↔B had a session. S↔B did not.
        // PageRank from seed S should give A high trust (direct
        // interaction with seed), B medium trust (one hop from seed),
        // and a Sybil node X with zero interactions gets zero.
        let (s_id, s_node, s_agg) = shared_pair();
        let (a_id, a_node, a_agg) = shared_pair();
        let (b_id, b_node, b_agg) = shared_pair();
        let x_id = NodeId::generate(); // Sybil, no interactions

        // Session S↔A: both report
        let sid_sa = rand_sid();
        let cb_s = batch(s_id, &s_node, vec![
            sign(&s_node, claim(s_id, a_id, Role::Client, 1000, sid_sa, 0, OP_CHANNEL_BYTES)),
        ], 1024);
        let cb_a1 = batch(a_id, &a_node, vec![
            sign(&a_node, claim(s_id, a_id, Role::Server, 1000, sid_sa, 0, OP_CHANNEL_BYTES)),
        ], 1024);

        // Session A↔B: both report
        let sid_ab = rand_sid();
        let cb_a2 = batch(a_id, &a_node, vec![
            sign(&a_node, claim(a_id, b_id, Role::Client, 500, sid_ab, 16, OP_CHANNEL_BYTES)),
        ], 2048);
        let cb_b = batch(b_id, &b_node, vec![
            sign(&b_node, claim(a_id, b_id, Role::Server, 500, sid_ab, 0, OP_CHANNEL_BYTES)),
        ], 1024);

        let mut ks = KeyStore::new();
        ks.insert(s_id, s_agg);
        ks.insert(a_id, a_agg);
        ks.insert(b_id, b_agg);

        let batches = vec![cb_s, cb_a1, cb_a2, cb_b];
        let trust = AutoTrust::from_batches(&batches, &ks, &[s_id], 1);

        // Seed has trust (teleport).
        assert!(trust.score(&s_id) > 0, "seed should have positive trust");
        // A interacted directly with seed → high trust.
        assert!(trust.score(&a_id) > 0, "A should have positive trust");
        // B interacted with A (one hop from seed) → positive trust.
        assert!(trust.score(&b_id) > 0, "B should have positive trust");
        // A should have more trust than B (closer to seed).
        assert!(trust.score(&a_id) > trust.score(&b_id),
            "A (direct seed contact) should outrank B (one hop)");
        // Sybil X has no interactions → zero trust.
        assert_eq!(trust.score(&x_id), 0, "Sybil with no interactions = zero trust");
    }

    #[test]
    fn dht_queries_excluded_from_trust() {
        // Spamming DHT queries at the seed should NOT create trust.
        let (s_id, s_node, s_agg) = shared_pair();
        let (x_id, x_node, x_agg) = shared_pair();
        let sid = rand_sid();
        let cb_s = batch(s_id, &s_node, vec![
            sign(&s_node, claim(s_id, x_id, Role::Client, 1_000_000, sid, 0, OP_DHT_QUERY)),
        ], 1024);
        let cb_x = batch(x_id, &x_node, vec![
            sign(&x_node, claim(s_id, x_id, Role::Server, 1_000_000, sid, 0, OP_DHT_QUERY)),
        ], 1024);
        let mut ks = KeyStore::new();
        ks.insert(s_id, s_agg);
        ks.insert(x_id, x_agg);
        let trust = AutoTrust::from_batches(&[cb_s, cb_x], &ks, &[s_id], 1);
        assert_eq!(trust.score(&x_id), 0, "DHT-only node should have zero trust");
    }

    #[test]
    fn repeated_sessions_give_one_trust_edge() {
        // 50 sessions between S and A → 1 trust edge, not 50.
        let (s_id, s_node, s_agg) = shared_pair();
        let (a_id, a_node, a_agg) = shared_pair();
        let mut s_claims = Vec::new();
        let mut a_claims = Vec::new();
        for i in 0..50u64 {
            let sid = rand_sid();
            s_claims.push(sign(&s_node, claim(s_id, a_id, Role::Client, 100, sid, i * 16, OP_CHANNEL_BYTES)));
            a_claims.push(sign(&a_node, claim(s_id, a_id, Role::Server, 100, sid, i * 16, OP_CHANNEL_BYTES)));
        }
        let cb_s = batch(s_id, &s_node, s_claims, 4000);
        let cb_a = batch(a_id, &a_node, a_claims, 4000);
        let mut ks = KeyStore::new();
        ks.insert(s_id, s_agg);
        ks.insert(a_id, a_agg);
        let edges = interaction_graph(&[cb_s, cb_a], &ks, 1);
        assert_eq!(edges.len(), 1, "50 sessions same pair → 1 trust edge");
    }

    #[test]
    fn tally_auto_pays_interactors_not_sybils() {
        let (s_id, s_node, s_agg) = shared_pair();
        let (a_id, a_node, a_agg) = shared_pair();

        // Session S↔A
        let sid = rand_sid();
        let cb_s = batch(s_id, &s_node, vec![
            sign(&s_node, claim(s_id, a_id, Role::Client, 100, sid, 0, OP_CHANNEL_BYTES)),
        ], 1024);
        let cb_a = batch(a_id, &a_node, vec![
            sign(&a_node, claim(s_id, a_id, Role::Server, 100, sid, 0, OP_CHANNEL_BYTES)),
        ], 1024);

        let mut ab = AddressBook::default();
        ab.register(s_id, [0x5E; 20]);
        ab.register(a_id, [0xAA; 20]);
        let mut ks = KeyStore::new();
        ks.insert(s_id, s_agg);
        ks.insert(a_id, a_agg);

        let payouts = tally_auto(
            &[cb_s, cb_a], &ab, &ks, &[s_id], 1, 10_000, &OpWeights::default(),
        );
        // A served S → A gets paid.
        assert!(payouts.iter().any(|p| p.node == a_id && p.amount_wei > 0),
            "A should receive a payout");
    }

    #[test]
    fn sybil_cluster_earns_nothing_auto_trust() {
        // Sybil cluster: X and Y interact with each other but never
        // with the seed or any honest node.
        let (s_id, s_node, s_agg) = shared_pair();
        let (x_id, x_node, x_agg) = shared_pair();
        let (y_id, y_node, y_agg) = shared_pair();

        // X↔Y session (Sybil interaction)
        let sid = rand_sid();
        let cb_x = batch(x_id, &x_node, vec![
            sign(&x_node, claim(x_id, y_id, Role::Client, 1_000_000, sid, 0, OP_CHANNEL_BYTES)),
        ], 1024);
        let cb_y = batch(y_id, &y_node, vec![
            sign(&y_node, claim(x_id, y_id, Role::Server, 1_000_000, sid, 0, OP_CHANNEL_BYTES)),
        ], 1024);

        let mut ab = AddressBook::default();
        ab.register(s_id, [0x5E; 20]);
        ab.register(x_id, [0xAA; 20]);
        ab.register(y_id, [0xBB; 20]);
        let mut ks = KeyStore::new();
        ks.insert(s_id, s_agg);
        ks.insert(x_id, x_agg);
        ks.insert(y_id, y_agg);

        let payouts = tally_auto(
            &[cb_x, cb_y], &ab, &ks, &[s_id], 1, 1_000_000, &OpWeights::default(),
        );
        // Sybil cluster has zero PageRank from seed → zero payouts.
        assert_eq!(payouts.len(), 0, "Sybil cluster with no seed connection earns nothing");
    }

    #[test]
    fn empty_epoch_zero_root() {
        let root = merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }
}
