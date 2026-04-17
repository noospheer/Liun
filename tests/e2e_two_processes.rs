//! # Two-Process Test
//!
//! Simulates two independent nodes as separate tasks with independent
//! state, communicating over localhost TCP. Each node:
//! 1. Initializes its own storage directory
//! 2. Bootstraps a shared PSK
//! 3. Handshakes over TCP
//! 4. Runs Liu exchange
//! 5. Saves state
//! 6. "Restarts" (drops state, reloads from disk)
//! 7. Verifies state survived the restart
//!
//! This is the closest we can get to two separate machines
//! without actually running two binaries.

use liuproto_core::pool::Pool;
use liuproto_core::storage::StateDir;
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use liun_channel::handshake::{self, HandshakeResult};
use liun_overlay::bootstrap::{BootstrapConfig, bootstrap_psk};
use tokio::net::{TcpListener, TcpStream};
use std::path::PathBuf;

fn test_state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("liun_e2e_{}_{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test]
async fn test_two_nodes_full_lifecycle() {
    println!("\n═══════════════════════════════════════════");
    println!("  TWO-NODE LIFECYCLE TEST");
    println!("═══════════════════════════════════════════\n");

    let node_a_id: u64 = 1;
    let node_b_id: u64 = 2;
    let dir_a = test_state_dir("node_a");
    let dir_b = test_state_dir("node_b");

    // ════════════════════════════════════════
    // Phase 1: Bootstrap PSK (no pre-shared key)
    // ════════════════════════════════════════
    println!("Phase 1: Bootstrap...");
    let config = BootstrapConfig { k: 10, psk_size: 2048 };
    let (psk_a, psk_b) = bootstrap_psk(&config);
    assert_eq!(psk_a, psk_b);
    println!("  PSK established (no pre-shared key)");

    // ════════════════════════════════════════
    // Phase 2: Both nodes initialize storage + save PSK
    // ════════════════════════════════════════
    println!("Phase 2: Initialize storage...");
    let state_a = StateDir::open(&dir_a).unwrap();
    state_a.save_node_id(node_a_id).unwrap();
    state_a.save_pool(node_b_id, 0, &psk_a).unwrap();
    state_a.save_trust_edges(&[(node_a_id, node_b_id, 1.0)]).unwrap();

    let state_b = StateDir::open(&dir_b).unwrap();
    state_b.save_node_id(node_b_id).unwrap();
    state_b.save_pool(node_a_id, 0, &psk_b).unwrap();
    state_b.save_trust_edges(&[(node_a_id, node_b_id, 1.0)]).unwrap();
    println!("  Both nodes saved state to disk");

    // ════════════════════════════════════════
    // Phase 3: Handshake over TCP
    // ════════════════════════════════════════
    println!("Phase 3: Handshake...");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let hs_bob = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        handshake::handshake_respond(&mut stream, node_b_id, 0, &[node_a_id]).await.unwrap()
    });

    let hs_alice = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        handshake::handshake_initiate(&mut stream, node_a_id, 0, &[node_b_id]).await.unwrap()
    });

    let alice_hs = hs_alice.await.unwrap();
    let bob_hs = hs_bob.await.unwrap();

    match &alice_hs {
        HandshakeResult::Ready { peer_id, .. } => {
            assert_eq!(*peer_id, node_b_id);
            println!("  Alice ↔ Bob: handshake READY");
        }
        other => panic!("Alice handshake failed: {:?}", other),
    }
    match &bob_hs {
        HandshakeResult::Ready { peer_id, .. } => assert_eq!(*peer_id, node_a_id),
        other => panic!("Bob handshake failed: {:?}", other),
    }

    // ════════════════════════════════════════
    // Phase 4: Liu exchange
    // ════════════════════════════════════════
    println!("Phase 4: Liu exchange...");
    let params = ExchangeParams::new(2000, 0.1, 0.5);
    let nonce = [0u8; 16];

    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let psk_b2 = psk_b.clone();
    let params2 = params.clone();
    let bob_ex = tokio::spawn(async move {
        let (mut stream, _) = listener2.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&psk_b2, &nonce);
        run_as_bob(&mut stream, &mut pool, &params2).await.unwrap()
    });

    let psk_a2 = psk_a.clone();
    let alice_ex = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr2).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&psk_a2, &nonce);
        run_as_alice(&mut stream, &mut pool, &params).await.unwrap()
    });

    let alice_result = alice_ex.await.unwrap();
    let bob_result = bob_ex.await.unwrap();

    assert!(alice_result.verified, "Alice MAC failed");
    assert!(bob_result.verified, "Bob MAC failed");
    assert_eq!(alice_result.sign_bits, bob_result.sign_bits);
    println!("  {} ITS sign bits agreed", alice_result.sign_bits.len());

    // ════════════════════════════════════════
    // Phase 5: Save post-exchange state
    // ════════════════════════════════════════
    println!("Phase 5: Save state...");
    let state_a = StateDir::open(&dir_a).unwrap();
    state_a.save_channel_meta(node_b_id, 2000, "active").unwrap();

    let state_b = StateDir::open(&dir_b).unwrap();
    state_b.save_channel_meta(node_a_id, 2000, "active").unwrap();
    println!("  State saved to disk");

    // ════════════════════════════════════════
    // Phase 6: "Restart" — drop everything, reload from disk
    // ════════════════════════════════════════
    println!("Phase 6: Simulate restart...");

    // Node A restarts
    let state_a_new = StateDir::open(&dir_a).unwrap();
    let restored_id_a = state_a_new.load_node_id().unwrap().unwrap();
    let restored_peers_a = state_a_new.list_peers().unwrap();
    let restored_edges_a = state_a_new.load_trust_edges().unwrap().unwrap();
    let (restored_bits_a, restored_status_a) = state_a_new.load_channel_meta(node_b_id).unwrap().unwrap();

    assert_eq!(restored_id_a, node_a_id);
    assert_eq!(restored_peers_a, vec![node_b_id]);
    assert_eq!(restored_edges_a.len(), 1);
    assert_eq!(restored_bits_a, 2000);
    assert_eq!(restored_status_a, "active");
    println!("  Node A restored: id={}, peers={:?}, bits={}, status={}",
        restored_id_a, restored_peers_a, restored_bits_a, restored_status_a);

    // Node B restarts
    let state_b_new = StateDir::open(&dir_b).unwrap();
    let restored_id_b = state_b_new.load_node_id().unwrap().unwrap();
    let restored_peers_b = state_b_new.list_peers().unwrap();
    let (restored_bits_b, restored_status_b) = state_b_new.load_channel_meta(node_a_id).unwrap().unwrap();

    assert_eq!(restored_id_b, node_b_id);
    assert_eq!(restored_peers_b, vec![node_a_id]);
    assert_eq!(restored_bits_b, 2000);
    println!("  Node B restored: id={}, peers={:?}, bits={}, status={}",
        restored_id_b, restored_peers_b, restored_bits_b, restored_status_b);

    // ════════════════════════════════════════
    // Phase 7: Reconnect after restart
    // ════════════════════════════════════════
    println!("Phase 7: Reconnect after restart...");

    let listener3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr3 = listener3.local_addr().unwrap();

    let peers_b = restored_peers_b.clone();
    let reconnect_bob = tokio::spawn(async move {
        let (mut stream, _) = listener3.accept().await.unwrap();
        handshake::handshake_respond(&mut stream, node_b_id, 0, &peers_b).await.unwrap()
    });

    let peers_a = restored_peers_a.clone();
    let reconnect_alice = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr3).await.unwrap();
        handshake::handshake_initiate(&mut stream, node_a_id, 0, &peers_a).await.unwrap()
    });

    let ra = reconnect_alice.await.unwrap();
    let rb = reconnect_bob.await.unwrap();

    match ra {
        HandshakeResult::Ready { peer_id, .. } => {
            assert_eq!(peer_id, node_b_id);
            println!("  Reconnected: Alice ↔ Bob READY");
        }
        other => panic!("reconnect failed: {:?}", other),
    }
    match rb {
        HandshakeResult::Ready { peer_id, .. } => assert_eq!(peer_id, node_a_id),
        other => panic!("reconnect failed: {:?}", other),
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    println!("\n═══════════════════════════════════════════");
    println!("  LIFECYCLE TEST COMPLETE");
    println!("  Bootstrap: no pre-shared key ✓");
    println!("  Handshake: mutual identification ✓");
    println!("  Exchange: 2000 ITS sign bits agreed ✓");
    println!("  Persist: state saved to disk ✓");
    println!("  Restart: state restored from disk ✓");
    println!("  Reconnect: handshake after restart ✓");
    println!("═══════════════════════════════════════════\n");
}
