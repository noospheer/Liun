//! # OpRecorder: node-side session accumulator + off-data-path reporter
//!
//! A node (relay, DHT, channel endpoint) keeps one `OpRecorder` per
//! process. For each active session with a counterparty it tracks a
//! single running `total_count` in memory — **no wire traffic on the
//! data path**. At session close the recorder produces one signed
//! [`ReceiptClaim`] and stashes it for the next batch post.
//!
//! The counterparty does exactly the same thing, independently. The
//! aggregator later pairs the two by `(epoch, session_id)` and
//! credits `min(client.total, server.total)`.
//!
//! ## Usage sketch
//!
//! ```ignore
//! let recorder = OpRecorder::new(my_id, shared_key);
//! let session = recorder.start_session(counterparty_id, Role::Server, OP_CHANNEL_BYTES);
//! // ... handle traffic; report observed bytes as you go ...
//! session.observe(1500);
//! session.observe(1500);
//! // ... session ends ...
//! recorder.close_session(session, epoch);
//! // Later, at batch time:
//! let batch = recorder.build_batch(epoch).unwrap();
//! // Post `batch` to the aggregator out-of-band.
//! ```
//!
//! ## Session ID discipline
//!
//! The initiator of the session (usually the client) picks a fresh
//! 16-byte `session_id` (ITS-random) and sends it to the counterparty
//! as part of the first protocol message (handshake, request header,
//! etc. — one ~16 byte addition to existing wire, negligible).
//! Both sides use the same `session_id` when they close out.
//!
//! `SharedKey` offsets are chosen from a monotonic per-recorder
//! counter so neither party reuses key material.

use crate::{
    sign_claim, ClaimBatch, Error, MacKey, ReceiptClaim, Role, SharedKey, SignedClaim,
};
use liuproto_core::identity::NodeId;
use std::sync::Mutex;

pub struct OpRecorder {
    node_id: NodeId,
    key: SharedKey,
    inner: Mutex<Inner>,
}

struct Inner {
    next_offset: u64,
    pending: Vec<SignedClaim>,
    /// Long-running per-peer sessions keyed by `(counterparty, op_kind)`.
    /// First observation opens one; subsequent observations bump the
    /// counter; `flush_long_sessions` closes them all at epoch rollover.
    ///
    /// Useful for sub-byte ops like DHT queries where a dedicated
    /// start/observe/close per op would bloat the pending vector.
    long_sessions: std::collections::HashMap<(NodeId, u8), Session>,
}

impl OpRecorder {
    pub fn new(node_id: NodeId, key: SharedKey) -> Self {
        Self {
            node_id,
            key,
            inner: Mutex::new(Inner {
                next_offset: 0,
                pending: Vec::new(),
                long_sessions: std::collections::HashMap::new(),
            }),
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Reserve the next 16-byte chunk of the shared key stream.
    fn reserve_offset(&self) -> u64 {
        let mut i = self.inner.lock().unwrap();
        let o = i.next_offset;
        i.next_offset += 16;
        o
    }

    /// Begin tracking a session. `counterparty` is the *other* node's
    /// ID; `my_role` is whether *this* node acts as client or server;
    /// `op_kind` classifies the traffic.
    pub fn start_session(
        &self,
        counterparty: NodeId,
        my_role: Role,
        op_kind: u8,
    ) -> Session {
        let offset = self.reserve_offset();
        let session_id = {
            let mut sid = [0u8; 16];
            getrandom::fill(&mut sid).unwrap();
            sid
        };
        Session {
            counterparty,
            my_role,
            op_kind,
            session_id,
            key_offset: offset,
            total_count: 0,
        }
    }

    /// Begin tracking a session with an externally-provided `session_id`
    /// (for the **responder** side — the client proposes the session_id
    /// via the first message, the server adopts it here).
    pub fn join_session(
        &self,
        counterparty: NodeId,
        my_role: Role,
        op_kind: u8,
        session_id: [u8; 16],
    ) -> Session {
        let offset = self.reserve_offset();
        Session {
            counterparty,
            my_role,
            op_kind,
            session_id,
            key_offset: offset,
            total_count: 0,
        }
    }

    /// Finish a session and stash a signed claim for later batching.
    pub fn close_session(&self, session: Session, epoch: u32) -> Result<(), Error> {
        let (client_id, server_id) = match session.my_role {
            Role::Client => (self.node_id, session.counterparty),
            Role::Server => (session.counterparty, self.node_id),
        };
        let claim = ReceiptClaim {
            client_id,
            server_id,
            epoch,
            op_kind: session.op_kind,
            total_count: session.total_count,
            session_id: session.session_id,
            key_offset: session.key_offset,
            role: session.my_role,
        };
        let key: MacKey = self.key.key_at(session.key_offset as usize)?;
        let signed = sign_claim(claim, &key);
        self.inner.lock().unwrap().pending.push(signed);
        Ok(())
    }

    /// Produce a `ClaimBatch` from all pending signed claims and reset
    /// the pending buffer. The caller posts the batch to the aggregator
    /// (e.g. via EIP-4844 blob or direct HTTP).
    pub fn build_batch(&self, epoch: u32) -> Result<ClaimBatch, Error> {
        let claims: Vec<SignedClaim> = std::mem::take(&mut self.inner.lock().unwrap().pending);
        if claims.is_empty() {
            return Err(Error::KeyExhausted); // misuse: nothing to post
        }
        let batch_offset = self.reserve_offset();
        let key = self.key.key_at(batch_offset as usize)?;
        Ok(ClaimBatch::sign(
            epoch,
            self.node_id,
            claims,
            &key,
            batch_offset,
        ))
    }

    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap().pending.len()
    }

    /// Observe `n` bytes/ops on a long-running per-peer session. First
    /// call for a given `(counterparty, op_kind)` pair opens the session;
    /// subsequent calls bump the counter. `my_role` records whether this
    /// node is the client or server for the session (determined by the
    /// caller based on protocol context).
    ///
    /// Call [`flush_long_sessions`] periodically (e.g. on epoch rollover)
    /// to materialize the long-running sessions into signed claims.
    ///
    /// Useful for small-op paths (DHT PING/FIND, DNS-style RPC) where a
    /// fresh signed claim per op would bloat the pending vector.
    pub fn observe_peer(
        &self,
        counterparty: NodeId,
        my_role: Role,
        op_kind: u8,
        n: u64,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let key = (counterparty, op_kind);
        if let Some(s) = inner.long_sessions.get_mut(&key) {
            s.total_count = s.total_count.saturating_add(n);
            return;
        }
        // Lazy-create a new session. Reserve an offset inline.
        let offset = inner.next_offset;
        inner.next_offset += 16;
        let mut sid = [0u8; 16];
        getrandom::fill(&mut sid).unwrap();
        let mut s = Session {
            counterparty,
            my_role,
            op_kind,
            session_id: sid,
            key_offset: offset,
            total_count: 0,
        };
        s.observe(n);
        inner.long_sessions.insert(key, s);
    }

    /// Returns the session_id of an existing long session for
    /// `(counterparty, op_kind)`, if one is open. Callers on the
    /// *responder* side (server) should use this to propose their
    /// `session_id` to the counterparty via the protocol's
    /// existing fields (e.g. DHT response adds the `session_id` once).
    ///
    /// For asymmetric discovery (caller doesn't yet know what
    /// `session_id` the server will use), the client must learn it
    /// from the first response. Since the aggregator pairs by
    /// `(epoch, session_id)`, mismatched session_ids mean no pairing
    /// → no credit. Getting both sides to agree on the id is the
    /// only wire detail that needs attention.
    pub fn peek_long_session_id(
        &self,
        counterparty: NodeId,
        op_kind: u8,
    ) -> Option<[u8; 16]> {
        self.inner
            .lock()
            .unwrap()
            .long_sessions
            .get(&(counterparty, op_kind))
            .map(|s| s.session_id)
    }

    /// Join or refresh a long session with an **externally-supplied**
    /// session_id (for the responder side that adopts the id sent by
    /// the initiator). First call opens the session; later calls are
    /// no-ops (keep the id stable across the epoch).
    pub fn join_long_session(
        &self,
        counterparty: NodeId,
        my_role: Role,
        op_kind: u8,
        session_id: [u8; 16],
    ) {
        let mut inner = self.inner.lock().unwrap();
        let key = (counterparty, op_kind);
        if inner.long_sessions.contains_key(&key) {
            return;
        }
        let offset = inner.next_offset;
        inner.next_offset += 16;
        inner.long_sessions.insert(
            key,
            Session {
                counterparty,
                my_role,
                op_kind,
                session_id,
                key_offset: offset,
                total_count: 0,
            },
        );
    }

    /// Drain all long-running sessions into signed claims. Call once
    /// per epoch boundary; after this, the next `observe_peer` call
    /// opens fresh sessions for the new epoch.
    pub fn flush_long_sessions(&self, epoch: u32) -> Result<usize, crate::Error> {
        let sessions: Vec<Session> = {
            let mut inner = self.inner.lock().unwrap();
            inner.long_sessions.drain().map(|(_, s)| s).collect()
        };
        let mut count = 0;
        for s in sessions {
            if s.total_count > 0 {
                self.close_session(s, epoch)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Number of open long-running sessions.
    pub fn long_session_count(&self) -> usize {
        self.inner.lock().unwrap().long_sessions.len()
    }
}

/// Handle to an active session — just a counter + metadata. No wire
/// presence; purely in-memory on the node.
#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub counterparty: NodeId,
    pub my_role: Role,
    pub op_kind: u8,
    pub session_id: [u8; 16],
    pub key_offset: u64,
    pub total_count: u64,
}

impl Session {
    /// Register `n` bytes/ops observed on this session.
    pub fn observe(&mut self, n: u64) {
        self.total_count = self.total_count.saturating_add(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OP_CHANNEL_BYTES, OP_RELAY_SHARE};

    fn rand_bytes(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        getrandom::fill(&mut v).unwrap();
        v
    }

    #[test]
    fn session_lifecycle_produces_signed_claim() {
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let rec = OpRecorder::new(me, SharedKey::from_bytes(rand_bytes(4096)));

        let mut s = rec.start_session(peer, Role::Server, OP_RELAY_SHARE);
        s.observe(500);
        s.observe(1500);
        assert_eq!(s.total_count, 2000);
        rec.close_session(s, 5).unwrap();

        assert_eq!(rec.pending_count(), 1);
    }

    #[test]
    fn client_proposes_server_joins_same_session_id() {
        let client_id = NodeId::generate();
        let server_id = NodeId::generate();
        let client_rec = OpRecorder::new(client_id, SharedKey::from_bytes(rand_bytes(4096)));
        let server_rec = OpRecorder::new(server_id, SharedKey::from_bytes(rand_bytes(4096)));

        let cs = client_rec.start_session(server_id, Role::Client, OP_CHANNEL_BYTES);
        let ss = server_rec.join_session(client_id, Role::Server, OP_CHANNEL_BYTES, cs.session_id);
        assert_eq!(cs.session_id, ss.session_id);
    }

    #[test]
    fn observe_peer_aggregates_across_calls() {
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let rec = OpRecorder::new(me, SharedKey::from_bytes(rand_bytes(4096)));
        rec.observe_peer(peer, Role::Server, OP_RELAY_SHARE, 100);
        rec.observe_peer(peer, Role::Server, OP_RELAY_SHARE, 250);
        rec.observe_peer(peer, Role::Server, OP_RELAY_SHARE, 1);
        assert_eq!(rec.long_session_count(), 1);

        let n = rec.flush_long_sessions(42).unwrap();
        assert_eq!(n, 1);
        assert_eq!(rec.long_session_count(), 0);
        assert_eq!(rec.pending_count(), 1);
    }

    #[test]
    fn observe_peer_separates_by_op_kind() {
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let rec = OpRecorder::new(me, SharedKey::from_bytes(rand_bytes(4096)));
        rec.observe_peer(peer, Role::Server, OP_RELAY_SHARE, 10);
        rec.observe_peer(peer, Role::Server, OP_CHANNEL_BYTES, 10);
        assert_eq!(rec.long_session_count(), 2);
    }

    #[test]
    fn join_long_session_then_observe_uses_shared_id() {
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let rec = OpRecorder::new(me, SharedKey::from_bytes(rand_bytes(4096)));
        let sid = [0xABu8; 16];
        rec.join_long_session(peer, Role::Server, OP_RELAY_SHARE, sid);
        rec.observe_peer(peer, Role::Server, OP_RELAY_SHARE, 42);

        assert_eq!(
            rec.peek_long_session_id(peer, OP_RELAY_SHARE),
            Some(sid),
            "observe_peer must reuse the joined session_id"
        );
    }

    #[test]
    fn flush_skips_empty_sessions() {
        // An opened but unused session shouldn't materialize a claim.
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let rec = OpRecorder::new(me, SharedKey::from_bytes(rand_bytes(4096)));
        rec.join_long_session(peer, Role::Server, OP_RELAY_SHARE, [1u8; 16]);
        let n = rec.flush_long_sessions(1).unwrap();
        assert_eq!(n, 0);
        assert_eq!(rec.pending_count(), 0);
    }

    #[test]
    fn build_batch_collects_pending() {
        let me = NodeId::generate();
        let peer = NodeId::generate();
        let key_bytes = rand_bytes(4096);
        let rec = OpRecorder::new(me, SharedKey::from_bytes(key_bytes.clone()));

        for i in 0..3u64 {
            let mut s = rec.start_session(peer, Role::Server, OP_RELAY_SHARE);
            s.observe(100 * (i + 1));
            rec.close_session(s, 1).unwrap();
        }
        let batch = rec.build_batch(1).unwrap();
        assert_eq!(batch.claims.len(), 3);
        // Verify with an aggregator-side copy of the same key.
        let agg_view = SharedKey::from_bytes(key_bytes);
        batch.verify(&agg_view).unwrap();
        assert_eq!(rec.pending_count(), 0);
    }
}
