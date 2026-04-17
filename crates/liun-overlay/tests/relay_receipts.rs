//! Integration test for the **off-data-path** receipt flow.
//!
//! Protocol on the wire: client POSTs a share advertising its NodeId
//! via `X-Liun-Client-Id` (no receipt halves, no MAC tags — just ~65
//! bytes of header). Both the relay and the client independently
//! track a session-level receipt in memory keyed by the same
//! `session_id` (derived deterministically from the HTTP session
//! string). At epoch close each side builds a `ClaimBatch`. Aggregator
//! pairs by `(epoch, session_id)` and credits the relay.

use liun_tally::{tally, AddressBook, KeyStore, OpWeights, TrustScore};
use liun_overlay::relay_client::post_share_as;
use liun_overlay::relay_server::{derive_session_id_test_hook, serve_with_recorder};
use liun_receipts::{OpRecorder, Role, SharedKey, OP_RELAY_SHARE};
use liuproto_core::identity::NodeId;
use std::sync::Arc;

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

#[tokio::test]
async fn off_path_session_receipt_tallies_correctly() {
    let client_id = NodeId::generate();
    let server_id = NodeId::generate();
    let epoch = 3u32;

    let client_bytes = rand_bytes(4096);
    let server_bytes = rand_bytes(4096);

    let client_rec = Arc::new(OpRecorder::new(
        client_id,
        SharedKey::from_bytes(client_bytes.clone()),
    ));
    let server_rec = Arc::new(OpRecorder::new(
        server_id,
        SharedKey::from_bytes(server_bytes.clone()),
    ));

    let handle = serve_with_recorder("127.0.0.1:0", server_rec.clone(), epoch)
        .await
        .expect("relay");
    let relay_url = format!("http://{}", handle.local_addr);

    let http_session = "test-session-01";
    let share = rand_bytes(256);

    // Client starts the same session locally (NO wire exchange for receipts).
    let sid_derived = derive_session_id_test_hook(http_session);
    let mut cs = client_rec.join_session(server_id, Role::Client, OP_RELAY_SHARE, sid_derived);
    cs.observe(share.len() as u64);

    post_share_as(&relay_url, http_session, &share, &client_id.to_base58())
        .await
        .expect("post");

    client_rec.close_session(cs, epoch).unwrap();

    let client_batch = client_rec.build_batch(epoch).expect("client batch");
    let server_batch = server_rec.build_batch(epoch).expect("server batch");

    let mut addr = AddressBook::default();
    addr.register(client_id, [0xC1; 20]);
    addr.register(server_id, [0x5E; 20]);

    let mut ks = KeyStore::new();
    ks.insert(client_id, SharedKey::from_bytes(client_bytes));
    ks.insert(server_id, SharedKey::from_bytes(server_bytes));

    let payouts = tally(
        &[client_batch, server_batch],
        &FlatTrust(1),
        &addr,
        &ks,
        10_000,
        &OpWeights::default(),
    );
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].node, server_id);
    assert_eq!(payouts[0].amount_wei, 10_000);
}

#[tokio::test]
async fn legacy_post_share_still_works_without_recorder() {
    use liun_overlay::relay_client::post_share;
    use liun_overlay::relay_server::serve;

    let handle = serve("127.0.0.1:0").await.expect("relay");
    let url = format!("http://{}", handle.local_addr);
    let share = rand_bytes(32);
    post_share(&url, "legacy-session", &share).await.expect("legacy post");
}
