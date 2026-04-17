//! Integration test: DHT `PING` and `FIND_NODE` queries get credited
//! to a long-running session on the responder, off the data path.

use liun_dht::{DhtConfig, DhtNode, DhtRecorderHook};
use liun_receipts::{OpRecorder, SharedKey};
use liuproto_core::identity::NodeId;
use std::sync::Arc;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

fn rand_port() -> u16 {
    // Let the OS pick via bind to 0 — we extract the real port after start.
    0
}

async fn spawn_node(recorder: Option<Arc<OpRecorder>>, epoch: u32) -> (DhtNode, u16) {
    let id = NodeId::generate();
    let cfg = DhtConfig::new(id, format!("127.0.0.1:{}", rand_port()).parse().unwrap(), 1234);
    let hook = recorder.map(|r| DhtRecorderHook { recorder: r, epoch });
    let node = DhtNode::start_with_recorder(cfg, hook).await.expect("start");
    let addr = node.local_addr().unwrap();
    (node, addr.port())
}

#[tokio::test]
async fn ping_credits_long_session_on_responder() {
    let responder_rec = Arc::new(OpRecorder::new(
        NodeId::generate(),
        SharedKey::from_bytes(rand_bytes(4096)),
    ));

    let (server, server_port) = spawn_node(Some(responder_rec.clone()), 7).await;
    let (client, _client_port) = spawn_node(None, 7).await;

    // Tell the client about the server; this sends a PING internally.
    client
        .bootstrap(
            server.our_id(),
            format!("127.0.0.1:{server_port}").parse().unwrap(),
        )
        .await
        .expect("bootstrap");

    // Give the server a moment to process.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Bootstrap sent a PING; responder should have one long session open
    // crediting the client's NodeId.
    assert_eq!(
        responder_rec.long_session_count(),
        1,
        "responder should have opened one long session from the PING"
    );

    // Flush → materialize as a signed claim.
    let flushed = responder_rec.flush_long_sessions(7).unwrap();
    assert_eq!(flushed, 1);
    assert_eq!(responder_rec.pending_count(), 1);
}

#[tokio::test]
async fn multiple_queries_from_same_peer_aggregate_to_one_session() {
    let responder_rec = Arc::new(OpRecorder::new(
        NodeId::generate(),
        SharedKey::from_bytes(rand_bytes(4096)),
    ));

    let (server, server_port) = spawn_node(Some(responder_rec.clone()), 1).await;
    let (client, _) = spawn_node(None, 1).await;

    // One PING via bootstrap.
    client
        .bootstrap(
            server.our_id(),
            format!("127.0.0.1:{server_port}").parse().unwrap(),
        )
        .await
        .expect("bootstrap");
    // Three more FIND_NODE queries.
    for _ in 0..3 {
        let _ = client.find_node(NodeId::generate()).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // All 4 queries credit the SAME (counterparty, op_kind) long session.
    assert_eq!(responder_rec.long_session_count(), 1);
}

#[tokio::test]
async fn no_recorder_is_noop() {
    let (server, server_port) = spawn_node(None, 0).await;
    let (client, _) = spawn_node(None, 0).await;
    client
        .bootstrap(
            server.our_id(),
            format!("127.0.0.1:{server_port}").parse().unwrap(),
        )
        .await
        .expect("bootstrap");
    // No panic, no deadlock. Just backwards-compatible DHT behavior.
}
