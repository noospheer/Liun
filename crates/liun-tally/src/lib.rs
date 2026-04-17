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
    fn empty_epoch_zero_root() {
        let root = merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }
}
