//! # liun-receipts: ITS session-level operation receipts
//!
//! The Liun protocol universe assumes **all computational crypto is
//! broken** — no ECDSA/Ed25519 signatures, no cryptographic hashes used
//! as commitments, no PRFs. Everything is information-theoretic:
//! one-time-pad encryption, Wegman-Carter MACs with fresh keys.
//!
//! Receipts therefore cannot be public-key signatures. We use
//! **Wegman-Carter polynomial MACs over GF(M61)** (the same primitive
//! the channel layer uses), each under a `SharedKey` established via a
//! Liu channel between the node and the aggregator.
//!
//! ## Phase 1 design: session-level, off the data path
//!
//! Earlier versions of this crate had client and server exchange
//! half-receipts **inline** on the live data path (e.g. via an HTTP
//! header) and combine them into a two-MAC `Receipt`. That imposed
//! ~300 bytes of wire overhead per op, which scales badly.
//!
//! The current design is the opposite:
//!
//!   * **One receipt per session**, not per op. Both parties keep a
//!     running counter; at session close each produces a single
//!     [`ReceiptClaim`] covering `total_count` bytes/ops.
//!   * **Each party MACs its own claim independently** under its own
//!     `SharedKey` with the aggregator. No inter-party MAC exchange.
//!   * **Claims travel off the hot path** to the aggregator, batched
//!     and posted periodically via a dedicated recorder daemon.
//!   * **Aggregator pairs claims** by `(epoch, session_id)`. A session
//!     is credited iff both the client's and server's claims arrive
//!     and agree. Credit = `min(client.total_count, server.total_count)`
//!     so neither side can inflate unilaterally.
//!
//! This drops wire overhead on the data path to zero and makes
//! Sybil resistance structural: an inflated server claim is worth
//! nothing unless a real client corroborates the same `session_id`.
//!
//! ## What's NOT ITS here
//!
//! * The Merkle tree used to commit the tally on Ethereum uses
//!   `keccak256`. That is a comp-crypto primitive, but it lives at the
//!   **Ethereum boundary** (the on-chain contract speaks keccak), not
//!   in the Liun protocol. The receipt layer itself uses zero hashes.
//! * Nothing in this crate depends on computational assumptions.

use liuproto_core::gf61::Gf61;
use liuproto_core::identity::NodeId;
use liuproto_core::mac::{mac_tag, mac_verify};
use thiserror::Error;

pub mod recorder;
pub use recorder::OpRecorder;

// Note on zeroization: `Gf61` (from liuproto-core) doesn't implement
// `Zeroize`, so `MacKey` cannot derive `ZeroizeOnDrop`. In practice
// `MacKey` wraps two u64 field elements that go out of scope after
// one MAC — per-call stack exposure is brief. `SharedKey` holds the
// long-lived buffer and we zero it manually via Drop.

pub const OP_RELAY_SHARE: u8 = 0;
pub const OP_DHT_QUERY: u8 = 1;
pub const OP_CHANNEL_BYTES: u8 = 2;

/// 16 bytes of fresh ITS-random material, reduced to a Wegman-Carter
/// MAC key `(r, s) ∈ GF(M61)²`.
#[derive(Clone, Copy, Debug)]
pub struct MacKey {
    pub r: Gf61,
    pub s: Gf61,
}

impl MacKey {
    pub fn from_bytes(b: [u8; 16]) -> Self {
        let r_raw = u64::from_le_bytes(b[..8].try_into().unwrap());
        let s_raw = u64::from_le_bytes(b[8..].try_into().unwrap());
        MacKey {
            r: Gf61::new(r_raw),
            s: Gf61::new(s_raw),
        }
    }
}

/// Per-pair stream of fresh key bytes established via a prior Liu
/// channel. Consumed 16 bytes at a time to derive `MacKey`s.
///
/// The buffer is zeroed on drop.
pub struct SharedKey {
    bytes: Vec<u8>,
    cursor: usize,
}

impl Drop for SharedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl SharedKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    pub fn withdraw(&mut self) -> Result<MacKey, Error> {
        if self.remaining() < 16 {
            return Err(Error::KeyExhausted);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.bytes[self.cursor..self.cursor + 16]);
        self.cursor += 16;
        Ok(MacKey::from_bytes(buf))
    }

    pub fn key_at(&self, offset: usize) -> Result<MacKey, Error> {
        if offset + 16 > self.bytes.len() {
            return Err(Error::KeyExhausted);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.bytes[offset..offset + 16]);
        Ok(MacKey::from_bytes(buf))
    }
}

/// 8-byte Wegman-Carter MAC tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacTag(pub u64);

impl MacTag {
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    pub fn from_bytes(b: [u8; 8]) -> Self {
        MacTag(u64::from_be_bytes(b))
    }
}

/// Who this claim is from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Client => 0,
            Role::Server => 1,
        }
    }
}

/// The canonical fields one party claims about a session. Serialized
/// deterministically for MAC input.
///
/// The `session_id` is the pairing key: client and server picked it
/// at session start (client proposes, server echoes). The aggregator
/// matches the two parties' claims for the same `(epoch, session_id)`
/// pair and credits `min(client.total_count, server.total_count)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReceiptClaim {
    pub client_id: NodeId,
    pub server_id: NodeId,
    pub epoch: u32,
    pub op_kind: u8,
    /// Total bytes/ops attributed to this session from the claimant's view.
    pub total_count: u64,
    /// Unique per-session identifier; pairing key at the aggregator.
    pub session_id: [u8; 16],
    /// Offset into the claimant's `SharedKey` used to derive the MAC key.
    pub key_offset: u64,
    /// Who produced this claim.
    pub role: Role,
}

impl ReceiptClaim {
    /// Fixed 134-byte serialization + implicit 8-byte domain separator
    /// appended by `coeffs()`.
    pub fn to_bytes(&self) -> [u8; 134] {
        let mut out = [0u8; 134];
        out[0..48].copy_from_slice(self.client_id.as_bytes());
        out[48..96].copy_from_slice(self.server_id.as_bytes());
        out[96..100].copy_from_slice(&self.epoch.to_be_bytes());
        out[100] = self.op_kind;
        out[101..109].copy_from_slice(&self.total_count.to_be_bytes());
        out[109..125].copy_from_slice(&self.session_id);
        out[125..133].copy_from_slice(&self.key_offset.to_be_bytes());
        out[133] = self.role.byte();
        out
    }

    /// MAC pre-image: serialized fields + 8-byte domain separator.
    /// Each byte maps to one `Gf61` coefficient (degree-142 polynomial
    /// over GF(M61); forgery ≤ 142 / M61 ≈ 6.2 × 10⁻¹⁷).
    fn coeffs(&self) -> Vec<Gf61> {
        let mut bytes = Vec::with_capacity(142);
        bytes.extend_from_slice(&self.to_bytes());
        bytes.extend_from_slice(b"lrcpt-v2");
        bytes.into_iter().map(|b| Gf61::new(b as u64)).collect()
    }
}

/// A signed session-level claim. One party's view of one session.
/// Off-data-path: posted to the aggregator via the recorder daemon.
#[derive(Clone, Copy, Debug)]
pub struct SignedClaim {
    pub claim: ReceiptClaim,
    pub tag: MacTag,
}

impl SignedClaim {
    pub const WIRE_LEN: usize = 134 + 8;

    pub fn to_wire(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..134].copy_from_slice(&self.claim.to_bytes());
        out[134..142].copy_from_slice(&self.tag.to_bytes());
        out
    }

    pub fn from_wire(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::WIRE_LEN {
            return Err(Error::BadWire);
        }
        let claim = decode_claim(&b[0..134])?;
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&b[134..142]);
        Ok(SignedClaim {
            claim,
            tag: MacTag::from_bytes(tag),
        })
    }
}

fn decode_claim(b: &[u8]) -> Result<ReceiptClaim, Error> {
    if b.len() != 134 {
        return Err(Error::BadWire);
    }
    let mut client = [0u8; 48];
    client.copy_from_slice(&b[0..48]);
    let mut server = [0u8; 48];
    server.copy_from_slice(&b[48..96]);
    let mut ep = [0u8; 4];
    ep.copy_from_slice(&b[96..100]);
    let mut tc = [0u8; 8];
    tc.copy_from_slice(&b[101..109]);
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&b[109..125]);
    let mut ko = [0u8; 8];
    ko.copy_from_slice(&b[125..133]);
    let role = match b[133] {
        0 => Role::Client,
        1 => Role::Server,
        _ => return Err(Error::BadWire),
    };
    Ok(ReceiptClaim {
        client_id: NodeId::from_bytes(client),
        server_id: NodeId::from_bytes(server),
        epoch: u32::from_be_bytes(ep),
        op_kind: b[100],
        total_count: u64::from_be_bytes(tc),
        session_id: sid,
        key_offset: u64::from_be_bytes(ko),
        role,
    })
}

/// A node's batch of signed claims for an epoch. Posted out-of-band
/// (e.g. via EIP-4844 blob or direct to aggregator) at epoch close.
#[derive(Clone, Debug)]
pub struct ClaimBatch {
    pub epoch: u32,
    pub reporter: NodeId,
    pub claims: Vec<SignedClaim>,
    pub batch_key_offset: u64,
    pub batch_tag: MacTag,
}

impl ClaimBatch {
    pub fn sign(
        epoch: u32,
        reporter: NodeId,
        claims: Vec<SignedClaim>,
        batch_key: &MacKey,
        batch_key_offset: u64,
    ) -> Self {
        let coeffs = batch_coeffs(epoch, &reporter, &claims);
        let tag = MacTag(mac_tag(&coeffs, batch_key.r, batch_key.s).val());
        Self {
            epoch,
            reporter,
            claims,
            batch_key_offset,
            batch_tag: tag,
        }
    }

    /// Verify batch MAC and every embedded claim's MAC, using the
    /// reporter's `SharedKey` with the aggregator.
    pub fn verify(&self, reporter_key: &SharedKey) -> Result<(), Error> {
        let bk = reporter_key.key_at(self.batch_key_offset as usize)?;
        let coeffs = batch_coeffs(self.epoch, &self.reporter, &self.claims);
        if !mac_verify(&coeffs, bk.r, bk.s, Gf61::new(self.batch_tag.0)) {
            return Err(Error::BadMac);
        }
        for c in &self.claims {
            // Every claim in this batch must be from the reporter.
            let claimant = match c.claim.role {
                Role::Client => c.claim.client_id,
                Role::Server => c.claim.server_id,
            };
            if claimant != self.reporter {
                return Err(Error::WrongReporter);
            }
            if c.claim.epoch != self.epoch {
                return Err(Error::WrongEpoch);
            }
            let k = reporter_key.key_at(c.claim.key_offset as usize)?;
            if !mac_verify(&c.claim.coeffs(), k.r, k.s, Gf61::new(c.tag.0)) {
                return Err(Error::BadMac);
            }
        }
        Ok(())
    }
}

fn batch_coeffs(epoch: u32, reporter: &NodeId, claims: &[SignedClaim]) -> Vec<Gf61> {
    let mut bytes = Vec::with_capacity(16 + 4 + 48 + 4 + claims.len() * (134 + 8));
    bytes.extend_from_slice(b"liun-batch-v2\x00\x00\x00");
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(reporter.as_bytes());
    bytes.extend_from_slice(&(claims.len() as u32).to_be_bytes());
    for c in claims {
        bytes.extend_from_slice(&c.claim.to_bytes());
        bytes.extend_from_slice(&c.tag.to_bytes());
    }
    bytes.into_iter().map(|b| Gf61::new(b as u64)).collect()
}

/// Sign one claim with a `MacKey` derived from the signer's
/// `SharedKey` at `claim.key_offset`.
pub fn sign_claim(claim: ReceiptClaim, key: &MacKey) -> SignedClaim {
    let tag = MacTag(mac_tag(&claim.coeffs(), key.r, key.s).val());
    SignedClaim { claim, tag }
}

/// Verify a standalone claim MAC under the given key.
pub fn verify_claim(signed: &SignedClaim, key: &MacKey) -> bool {
    mac_verify(
        &signed.claim.coeffs(),
        key.r,
        key.s,
        Gf61::new(signed.tag.0),
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("MAC did not verify")]
    BadMac,
    #[error("shared key stream exhausted at requested offset")]
    KeyExhausted,
    #[error("wire bytes malformed or wrong length")]
    BadWire,
    #[error("reporter does not match the claimant in the embedded claim")]
    WrongReporter,
    #[error("claim's epoch does not match batch epoch")]
    WrongEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        getrandom::fill(&mut v).unwrap();
        v
    }

    fn rand_session_id() -> [u8; 16] {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).unwrap();
        s
    }

    fn make_claim(
        client: NodeId,
        server: NodeId,
        role: Role,
        total: u64,
        session_id: [u8; 16],
        offset: u64,
    ) -> ReceiptClaim {
        ReceiptClaim {
            client_id: client,
            server_id: server,
            epoch: 1,
            op_kind: OP_CHANNEL_BYTES,
            total_count: total,
            session_id,
            key_offset: offset,
            role,
        }
    }

    #[test]
    fn claim_134_bytes_and_deterministic() {
        let c = make_claim(
            NodeId::generate(),
            NodeId::generate(),
            Role::Client,
            9999,
            [7u8; 16],
            64,
        );
        let a = c.to_bytes();
        let b = c.to_bytes();
        assert_eq!(a, b);
        assert_eq!(a.len(), 134);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let ck = SharedKey::from_bytes(rand_bytes(1024));
        let client = NodeId::generate();
        let server = NodeId::generate();
        let claim = make_claim(client, server, Role::Client, 100, rand_session_id(), 0);
        let key = ck.key_at(0).unwrap();
        let signed = sign_claim(claim, &key);
        assert!(verify_claim(&signed, &key));
    }

    #[test]
    fn tamper_with_total_count_fails_verify() {
        let ck = SharedKey::from_bytes(rand_bytes(1024));
        let client = NodeId::generate();
        let server = NodeId::generate();
        let claim = make_claim(client, server, Role::Client, 100, rand_session_id(), 0);
        let key = ck.key_at(0).unwrap();
        let mut signed = sign_claim(claim, &key);
        signed.claim.total_count = 9_999_999;
        assert!(!verify_claim(&signed, &key));
    }

    #[test]
    fn signed_claim_wire_roundtrip() {
        let ck = SharedKey::from_bytes(rand_bytes(1024));
        let claim = make_claim(
            NodeId::generate(),
            NodeId::generate(),
            Role::Server,
            42,
            rand_session_id(),
            16,
        );
        let signed = sign_claim(claim, &ck.key_at(16).unwrap());
        let wire = signed.to_wire();
        assert_eq!(wire.len(), SignedClaim::WIRE_LEN);
        let restored = SignedClaim::from_wire(&wire).unwrap();
        assert_eq!(restored.claim, signed.claim);
        assert_eq!(restored.tag, signed.tag);
    }

    #[test]
    fn batch_sign_and_verify() {
        let ck = SharedKey::from_bytes(rand_bytes(4096));
        let client = NodeId::generate();
        let server = NodeId::generate();
        // client-side batch: two claims in two distinct sessions
        let c1 = sign_claim(
            make_claim(client, server, Role::Client, 100, rand_session_id(), 0),
            &ck.key_at(0).unwrap(),
        );
        let c2 = sign_claim(
            make_claim(client, server, Role::Client, 200, rand_session_id(), 16),
            &ck.key_at(16).unwrap(),
        );
        let batch_off = 1024u64;
        let batch = ClaimBatch::sign(
            1,
            client,
            vec![c1, c2],
            &ck.key_at(batch_off as usize).unwrap(),
            batch_off,
        );
        batch.verify(&ck).expect("batch verifies");
    }

    #[test]
    fn batch_rejects_foreign_claim() {
        let ck = SharedKey::from_bytes(rand_bytes(4096));
        let client = NodeId::generate();
        let other = NodeId::generate();
        let server = NodeId::generate();
        // Claim where *other* is the client, but the batch reporter is `client`.
        let c = sign_claim(
            make_claim(other, server, Role::Client, 10, rand_session_id(), 0),
            &ck.key_at(0).unwrap(),
        );
        let batch_off = 1024u64;
        let batch = ClaimBatch::sign(
            1,
            client,
            vec![c],
            &ck.key_at(batch_off as usize).unwrap(),
            batch_off,
        );
        assert_eq!(batch.verify(&ck).unwrap_err(), Error::WrongReporter);
    }

    #[test]
    fn batch_rejects_tampered_list() {
        let ck = SharedKey::from_bytes(rand_bytes(4096));
        let client = NodeId::generate();
        let server = NodeId::generate();
        let c = sign_claim(
            make_claim(client, server, Role::Client, 100, rand_session_id(), 0),
            &ck.key_at(0).unwrap(),
        );
        let batch_off = 1024u64;
        let mut batch = ClaimBatch::sign(
            1,
            client,
            vec![c],
            &ck.key_at(batch_off as usize).unwrap(),
            batch_off,
        );
        // Attacker adds a second claim without re-MAC'ing the batch.
        batch.claims.push(sign_claim(
            make_claim(client, server, Role::Client, 999_999, rand_session_id(), 16),
            &ck.key_at(16).unwrap(),
        ));
        assert_eq!(batch.verify(&ck).unwrap_err(), Error::BadMac);
    }

    #[test]
    fn key_exhaustion_surfaces() {
        let sk = SharedKey::from_bytes(rand_bytes(15));
        assert_eq!(sk.key_at(0).unwrap_err(), Error::KeyExhausted);
    }
}
