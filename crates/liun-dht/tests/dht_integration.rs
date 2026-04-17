//! End-to-end DHT integration test.
//!
//! Spawn N nodes on localhost, bootstrap them from one seed, run lookups.

use liun_dht::{DhtConfig, DhtNode};
use liuproto_core::identity::NodeId;
use std::time::{Duration, Instant};

async fn spawn_node() -> DhtNode {
    // channel_port=0 in tests; we don't actually run a channel listener.
    let config = DhtConfig::new(NodeId::generate(), "127.0.0.1:0".parse().unwrap(), 0);
    DhtNode::start(config).await.expect("start DHT node")
}

/// Populate the routing table of every node by doing a find_node(our_id) on
/// each, iteratively causing them to discover each other through the seed.
async fn converge(nodes: &[DhtNode]) {
    // Each round, every node does a self-lookup. This walks them through the
    // network via iterative FIND_NODE and populates their routing tables.
    for _ in 0..3 {
        for n in nodes {
            let _ = n.find_node(n.our_id()).await;
        }
    }
}

#[tokio::test]
async fn test_20_node_mesh_converges_and_finds() {
    let n = 20;
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n { nodes.push(spawn_node().await); }

    // Make node 0 the seed. Everyone else PINGs node 0 to join.
    let seed_id = nodes[0].our_id();
    let seed_addr = nodes[0].local_addr().unwrap();
    for node in &nodes[1..] {
        node.bootstrap(seed_id, seed_addr).await
            .expect("bootstrap ping");
    }

    // Let the network converge.
    converge(&nodes).await;

    // Every node should have a non-trivial routing table now.
    let mut min_size = usize::MAX;
    let mut max_size = 0;
    for node in &nodes {
        let s = node.routing_size().await;
        min_size = min_size.min(s);
        max_size = max_size.max(s);
    }
    eprintln!("routing table sizes: min={min_size}, max={max_size}");
    assert!(min_size >= n / 2, "every node should know about at least half the network; min was {min_size}");

    // Now verify iterative find: from node 0, locate node N-1.
    let target_id = nodes[n - 1].our_id();
    let t0 = Instant::now();
    let result = nodes[0].find_node(target_id).await.expect("find_node");
    let elapsed = t0.elapsed();
    eprintln!("find_node converged in {elapsed:?}, returned {} contacts", result.len());

    // The target should be among the returned K closest.
    assert!(
        result.iter().any(|c| c.id == target_id),
        "target was not found in the returned contacts"
    );
}

#[tokio::test]
async fn test_find_cross_network() {
    let n = 15;
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n { nodes.push(spawn_node().await); }

    // Chain bootstrap: node i bootstraps from node 0 (simple star).
    let seed_id = nodes[0].our_id();
    let seed_addr = nodes[0].local_addr().unwrap();
    for node in &nodes[1..] {
        node.bootstrap(seed_id, seed_addr).await.unwrap();
    }

    converge(&nodes).await;

    // Every pair of nodes should be able to find each other.
    let mut successful = 0;
    let total = n * 5;  // sample 5 targets per source to keep test fast
    for i in 0..n {
        for j_off in 1..=5 {
            let j = (i + j_off) % n;
            if i == j { continue; }
            let target_id = nodes[j].our_id();
            if let Ok(result) = nodes[i].find_node(target_id).await {
                if result.iter().any(|c| c.id == target_id) {
                    successful += 1;
                }
            }
        }
    }
    eprintln!("cross-network lookups: {successful}/{total} succeeded");
    assert!(successful >= total * 9 / 10, "expected ≥90% success, got {successful}/{total}");
}

#[tokio::test]
async fn test_empty_bootstrap_fails_cleanly() {
    let node = spawn_node().await;
    // No bootstrap — routing table empty.
    let result = node.find_node(NodeId::generate()).await;
    assert!(matches!(result, Err(liun_dht::node::DhtError::RoutingTableEmpty)));
}

#[tokio::test]
async fn test_bootstrap_to_wrong_addr_times_out() {
    let node = spawn_node().await;
    let bogus = "127.0.0.1:1".parse().unwrap(); // nothing there
    let fake_id = NodeId::generate();
    let result = tokio::time::timeout(Duration::from_secs(3), node.bootstrap(fake_id, bogus)).await;
    match result {
        Ok(Err(_)) => {} // timed out and returned DhtError::Timeout — fine
        Ok(Ok(_)) => panic!("bootstrap to empty addr should fail"),
        Err(_) => panic!("test outer timeout fired — bootstrap hung"),
    }
}
