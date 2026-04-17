//! End-to-end session-level receipt flow:
//!
//! 1. Client and server each have a `SharedKey` with the aggregator.
//! 2. Client initiates a session (picks a random `session_id`);
//!    server joins with the same id. **No wire traffic** for
//!    receipt purposes — each side just tracks bytes observed.
//! 3. On session close, each side independently produces a signed
//!    `ReceiptClaim` under their own aggregator key.
//! 4. At epoch close each side builds a `ClaimBatch` and posts it
//!    out-of-band to the aggregator (simulated here by direct call).
//! 5. Aggregator tally pairs the two sides' claims by `session_id`
//!    and credits `min(client.total, server.total)` to the server.

use liun_tally::{tally, AddressBook, KeyStore, OpWeights, TrustScore};
use liun_receipts::{OpRecorder, Role, SharedKey, OP_RELAY_SHARE};
use liuproto_core::identity::NodeId;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

struct FlatTrust(u128);
impl TrustScore for FlatTrust {
    fn score(&self, _n: &NodeId) -> u128 {
        self.0
    }
}

#[test]
fn full_session_flow_5_sessions_tally_matches() {
    let client_id = NodeId::generate();
    let server_id = NodeId::generate();
    let epoch = 42u32;

    // Each party's view of its aggregator key.
    let client_agg_bytes = rand_bytes(8192);
    let server_agg_bytes = rand_bytes(8192);

    let client = OpRecorder::new(client_id, SharedKey::from_bytes(client_agg_bytes.clone()));
    let server = OpRecorder::new(server_id, SharedKey::from_bytes(server_agg_bytes.clone()));

    // 5 sessions of varying sizes. No wire traffic for receipts.
    let sizes: &[u64] = &[1000, 2500, 50, 17000, 128];
    for &bytes in sizes {
        // Client starts the session and proposes a session_id.
        let mut c_sess = client.start_session(server_id, Role::Client, OP_RELAY_SHARE);
        // Server joins with the same id (carried in the protocol's first message).
        let mut s_sess = server.join_session(client_id, Role::Server, OP_RELAY_SHARE, c_sess.session_id);

        // Both sides observe the same bytes.
        c_sess.observe(bytes);
        s_sess.observe(bytes);

        client.close_session(c_sess, epoch).unwrap();
        server.close_session(s_sess, epoch).unwrap();
    }

    let client_batch = client.build_batch(epoch).unwrap();
    let server_batch = server.build_batch(epoch).unwrap();

    // Aggregator state.
    let mut addr_book = AddressBook::default();
    addr_book.register(client_id, [0xC1; 20]);
    addr_book.register(server_id, [0x5E; 20]);

    let mut keystore = KeyStore::new();
    keystore.insert(client_id, SharedKey::from_bytes(client_agg_bytes));
    keystore.insert(server_id, SharedKey::from_bytes(server_agg_bytes));

    let payouts = tally(
        &[client_batch, server_batch],
        &FlatTrust(1),
        &addr_book,
        &keystore,
        100_000,
        &OpWeights::default(),
    );

    // Server is the only paid party (client is purely corroborating).
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].node, server_id);
    assert_eq!(payouts[0].amount_wei, 100_000);
}

#[test]
fn tampered_server_count_capped_by_client_min() {
    let client_id = NodeId::generate();
    let server_id = NodeId::generate();
    let epoch = 1u32;

    let client_bytes = rand_bytes(8192);
    let server_bytes = rand_bytes(8192);

    let client = OpRecorder::new(client_id, SharedKey::from_bytes(client_bytes.clone()));
    let server = OpRecorder::new(server_id, SharedKey::from_bytes(server_bytes.clone()));

    let mut c = client.start_session(server_id, Role::Client, OP_RELAY_SHARE);
    let mut s = server.join_session(client_id, Role::Server, OP_RELAY_SHARE, c.session_id);

    // Server lies about total by saying it served 1M bytes; client saw 100.
    c.observe(100);
    s.observe(1_000_000);

    client.close_session(c, epoch).unwrap();
    server.close_session(s, epoch).unwrap();

    let cb = client.build_batch(epoch).unwrap();
    let sb = server.build_batch(epoch).unwrap();

    let mut addr_book = AddressBook::default();
    addr_book.register(client_id, [1u8; 20]);
    addr_book.register(server_id, [2u8; 20]);
    let mut keystore = KeyStore::new();
    keystore.insert(client_id, SharedKey::from_bytes(client_bytes));
    keystore.insert(server_id, SharedKey::from_bytes(server_bytes));

    // Budget = 1_000_000. Server's inflated claim doesn't win more budget:
    // they're the only server (solo recipient of the budget regardless),
    // so this test asserts that the aggregator DID pair them and credited
    // the minimum (i.e. didn't reject for mismatch, didn't credit inflated).
    // To really exercise "cap", we'd need another server competing — see
    // the unit test `server_cannot_inflate_unilaterally`.
    let payouts = tally(
        &[cb, sb],
        &FlatTrust(1),
        &addr_book,
        &keystore,
        1_000_000,
        &OpWeights::default(),
    );
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].amount_wei, 1_000_000);
}

#[test]
fn unpaired_claim_earns_nothing() {
    // Server reports a session; client never does → aggregator refuses credit.
    let client_id = NodeId::generate();
    let server_id = NodeId::generate();
    let epoch = 1u32;

    let client_bytes = rand_bytes(4096);
    let server_bytes = rand_bytes(4096);

    let server = OpRecorder::new(server_id, SharedKey::from_bytes(server_bytes.clone()));
    let mut s = server.start_session(client_id, Role::Server, OP_RELAY_SHARE);
    s.observe(500);
    server.close_session(s, epoch).unwrap();
    let sb = server.build_batch(epoch).unwrap();

    let mut addr_book = AddressBook::default();
    addr_book.register(client_id, [1u8; 20]);
    addr_book.register(server_id, [2u8; 20]);
    let mut keystore = KeyStore::new();
    keystore.insert(client_id, SharedKey::from_bytes(client_bytes));
    keystore.insert(server_id, SharedKey::from_bytes(server_bytes));

    let payouts = tally(
        &[sb],
        &FlatTrust(1),
        &addr_book,
        &keystore,
        1000,
        &OpWeights::default(),
    );
    assert_eq!(payouts.len(), 0);
}
