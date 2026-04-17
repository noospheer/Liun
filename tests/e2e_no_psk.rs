//! # End-to-End Test: Two Strangers → ITS Key Agreement
//!
//! Two nodes that share NOTHING beforehand:
//! 1. Bootstrap a PSK via multi-path XOR (no pre-shared key)
//! 2. Establish a Liu channel using that PSK
//! 3. Run the signbit_nopa exchange over TCP
//! 4. Verify MACs and agree on shared sign bits
//!
//! This is the full Liun protocol: from zero trust to ITS key material.

use liun_overlay::bootstrap::{BootstrapConfig, bootstrap_psk};
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use liuproto_core::pool::Pool;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_strangers_to_its_key_agreement() {
    // ══════════════════════════════════════════════
    // Phase 0: Two nodes share NOTHING.
    // ══════════════════════════════════════════════

    // Phase 1: Multi-path bootstrap — derive shared PSK from
    // k independent network routes. No USB stick. No meeting.
    let config = BootstrapConfig { k: 20, psk_size: 2048 };
    let (alice_psk, bob_psk) = bootstrap_psk(&config);

    // Both derived the same PSK from network route diversity
    assert_eq!(alice_psk, bob_psk, "bootstrap PSK mismatch");
    assert!(alice_psk.len() >= 32, "PSK too short");

    // ══════════════════════════════════════════════
    // Phase 2: Establish Liu channel using bootstrapped PSK
    // ══════════════════════════════════════════════

    let nonce = [0u8; 16]; // In production: random per session
    let params = ExchangeParams::new(
        1000,   // 1000 sign bits per batch (small for test)
        0.1,    // cutoff
        0.5,    // mod_mult (σ/p = 2)
    );

    // Start TCP listener for Bob
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let bob_psk_clone = bob_psk.clone();
    let params_clone = params.clone();

    // ══════════════════════════════════════════════
    // Phase 3: Run Liu protocol exchange over TCP
    // ══════════════════════════════════════════════

    // Bob: accept connection, run as responder
    let bob_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&bob_psk_clone, &nonce);
        run_as_bob(&mut stream, &mut pool, &params_clone).await.unwrap()
    });

    // Alice: connect, run as initiator
    let alice_handle = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut pool = Pool::from_psk(&alice_psk, &nonce);
        run_as_alice(&mut stream, &mut pool, &params).await.unwrap()
    });

    let alice_result = alice_handle.await.unwrap();
    let bob_result = bob_handle.await.unwrap();

    // ══════════════════════════════════════════════
    // Phase 4: Verify — ITS key agreement succeeded
    // ══════════════════════════════════════════════

    // MACs verified both directions
    assert!(alice_result.verified, "Alice failed to verify Bob's MAC");
    assert!(bob_result.verified, "Bob failed to verify Alice's MAC");

    // Both produced sign bits
    assert_eq!(alice_result.sign_bits.len(), 1000);
    assert_eq!(bob_result.sign_bits.len(), 1000);

    // The sign bits AGREE — Alice and Bob now share ITS key material
    assert_eq!(
        alice_result.sign_bits, bob_result.sign_bits,
        "SIGN BITS DISAGREE — key agreement failed"
    );

    // Count the bits — should be roughly 50/50 (unbiased)
    let ones: usize = alice_result.sign_bits.iter().map(|&b| b as usize).sum();
    let zeros = 1000 - ones;
    assert!(ones > 400 && ones < 600,
        "sign bits biased: {ones} ones, {zeros} zeros");

    println!("════════════════════════════════════════");
    println!("  TWO STRANGERS → ITS KEY AGREEMENT");
    println!("  Bootstrap: 20-path XOR (no PSK needed)");
    println!("  Exchange: signbit_nopa over TCP");
    println!("  Result: 1000 shared ITS sign bits");
    println!("  MAC verified: both directions");
    println!("  Bits agree: YES");
    println!("  Bias: {ones}/1000 ones (unbiased ✓)");
    println!("════════════════════════════════════════");
}
