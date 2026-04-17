//! # 10-Node Full Mesh Test
//!
//! Every pair of 10 nodes:
//! 1. Bootstraps a PSK (no pre-shared key)
//! 2. Handshakes over TCP
//! 3. Runs Liu exchange
//! 4. Verifies MACs and sign bit agreement
//!
//! Then runs DKG + threshold signing + verification across all 10.
//! Total: 45 pairwise exchanges + DKG + signing + consensus.

use liuproto_core::gf61::Gf61;
use liuproto_core::pool::Pool;
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use liun_channel::handshake::{self, HandshakeResult};
use liun_overlay::bootstrap::{BootstrapConfig, bootstrap_psk};
use liun_overlay::trust::TrustGraph;
use liun_dkg::{Dkg, DkgParams, Contribution};
use liun_uss::signer::{PartialSigner, combine_signatures};
use liun_uss::verifier::Verifier;
use liun_uss::lagrange;
use liun_uss::shamir::Share;
use liun_consensus::{self, Attestation, BFT_THRESHOLD};
use liun_consensus::committee::{Committee, CommitteeConfig};
use tokio::net::{TcpListener, TcpStream};
use std::time::Instant;

const N: usize = 10;

#[tokio::test]
async fn test_ten_node_full_mesh() {
    let start = Instant::now();
    println!("\n═══════════════════════════════════════════");
    println!("  10-NODE FULL MESH TEST");
    println!("═══════════════════════════════════════════\n");

    // ════════════════════════════════════════
    // Phase 1: Bootstrap all 45 pairwise PSKs
    // ════════════════════════════════════════
    let t = Instant::now();
    let config = BootstrapConfig { k: 5, psk_size: 2048 };
    let mut psks = Vec::new(); // (i, j, psk)
    for i in 0..N {
        for j in (i+1)..N {
            let (a, b) = bootstrap_psk(&config);
            assert_eq!(a, b);
            psks.push((i, j, a));
        }
    }
    println!("Phase 1: {} PSKs bootstrapped in {:?}", psks.len(), t.elapsed());

    // ════════════════════════════════════════
    // Phase 2: Handshake every pair over TCP
    // ════════════════════════════════════════
    let t = Instant::now();
    let mut handshake_ok = 0;
    for i in 0..N {
        for j in (i+1)..N {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let peers_j = vec![i as u64]; // j knows i
            let peers_i = vec![j as u64]; // i knows j

            let bob = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                handshake::handshake_respond(&mut s, j as u64, 0, &peers_j).await.unwrap()
            });
            let alice = tokio::spawn(async move {
                let mut s = TcpStream::connect(addr).await.unwrap();
                handshake::handshake_initiate(&mut s, i as u64, 0, &peers_i).await.unwrap()
            });

            let ra = alice.await.unwrap();
            let rb = bob.await.unwrap();
            match (&ra, &rb) {
                (HandshakeResult::Ready { .. }, HandshakeResult::Ready { .. }) => {
                    handshake_ok += 1;
                }
                _ => panic!("handshake failed for pair ({i}, {j}): {:?} / {:?}", ra, rb),
            }
        }
    }
    println!("Phase 2: {handshake_ok}/45 handshakes OK in {:?}", t.elapsed());

    // ════════════════════════════════════════
    // Phase 3: Liu exchange every pair
    // ════════════════════════════════════════
    let t = Instant::now();
    let params = ExchangeParams::new(1000, 0.1, 0.5);
    let nonce = [0u8; 16];
    let mut exchange_ok = 0;
    let mut total_bits = 0usize;

    for &(i, j, ref psk) in &psks {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let psk_b = psk.clone();
        let psk_a = psk.clone();
        let p1 = params.clone();
        let p2 = params.clone();

        let bob = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut pool = Pool::from_psk(&psk_b, &nonce);
            run_as_bob(&mut s, &mut pool, &p1).await
        });
        let alice = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.set_nodelay(true).unwrap();
            let mut pool = Pool::from_psk(&psk_a, &nonce);
            run_as_alice(&mut s, &mut pool, &p2).await
        });

        let ra = alice.await.unwrap().unwrap();
        let rb = bob.await.unwrap().unwrap();
        assert!(ra.verified, "MAC failed for pair ({i},{j})");
        assert!(rb.verified, "MAC failed for pair ({i},{j})");
        assert_eq!(ra.sign_bits, rb.sign_bits, "bits disagree for pair ({i},{j})");
        total_bits += ra.sign_bits.len();
        exchange_ok += 1;
    }
    println!("Phase 3: {exchange_ok}/45 exchanges OK, {total_bits} total bits in {:?}", t.elapsed());

    // ════════════════════════════════════════
    // Phase 4: Trust graph
    // ════════════════════════════════════════
    let t = Instant::now();
    let mut graph = TrustGraph::new();
    for i in 0..N as u64 {
        for j in (i+1)..N as u64 {
            graph.add_channel(i, j, 1.0);
        }
    }
    let trust = graph.personalized_pagerank(0, 0.85, 20);
    let total_trust: f64 = trust.values().sum();
    println!("Phase 4: Trust computed in {:?} (total={total_trust:.3})", t.elapsed());

    // ════════════════════════════════════════
    // Phase 5: Committee selection
    // ════════════════════════════════════════
    let t = Instant::now();
    let cc = CommitteeConfig { target_size: 7, rotation_rate: 0.15, ..Default::default() };
    let mut committee = Committee::new(cc);
    committee.initialize(&trust);
    println!("Phase 5: Committee of {} selected in {:?}", committee.size(), t.elapsed());

    // ════════════════════════════════════════
    // Phase 6: DKG with full 10 nodes
    // ════════════════════════════════════════
    let t = Instant::now();
    let dkg_params = DkgParams::new(N);
    let mut contributions: Vec<Contribution> = Vec::new();
    for i in 0..N {
        let sb = liuproto_core::noise::random_bytes(8);
        let secret = Gf61::random(&sb.try_into().unwrap());
        contributions.push(Contribution::generate(i as u64, secret, &dkg_params));
    }
    let mut combined: Vec<Share> = Vec::new();
    for recv in 0..N {
        let mut dkg = Dkg::new(recv, dkg_params.clone());
        for sender in 0..N {
            dkg.receive_share(sender, contributions[sender].share_for(recv));
        }
        // Verify all senders
        for sender in 0..N {
            let all_shares: Vec<_> = (0..N).map(|r| contributions[sender].share_for(r)).collect();
            dkg.verify_sender(sender, &all_shares);
        }
        assert_eq!(dkg.honest_count(), N, "node {recv}: some senders excluded incorrectly");
        combined.push(dkg.combine());
    }
    let xs: Vec<Gf61> = combined.iter().map(|s| s.x).collect();
    let ys: Vec<Gf61> = combined.iter().map(|s| s.y).collect();
    let f0 = lagrange::reconstruct_secret(&xs, &ys);
    println!("Phase 6: DKG complete, F(0)={} in {:?}", f0, t.elapsed());

    // ════════════════════════════════════════
    // Phase 7: Sign 20 messages
    // ════════════════════════════════════════
    let t = Instant::now();
    let k = dkg_params.threshold;
    let signer_ids: Vec<u64> = combined[..k].iter().map(|s| s.x.val()).collect();
    let signers: Vec<PartialSigner> = combined[..k].iter()
        .map(|s| PartialSigner::new(s.x.val(), s.y)).collect();
    let verifier = Verifier::new(xs.clone(), ys.clone(), dkg_params.degree);

    let n_messages = 20;
    for m in 1..=n_messages {
        let msg = Gf61::new(m * 1000 + 42);
        let partials: Vec<Gf61> = signers.iter()
            .map(|s| s.partial_sign(msg, &signer_ids)).collect();
        let sig = combine_signatures(&partials);
        assert!(verifier.verify(msg, sig), "verify failed for message {m}");
        let fake = Gf61::new(sig.val().wrapping_add(1));
        assert!(!verifier.verify(msg, fake), "forgery not detected for message {m}");
    }
    println!("Phase 7: {n_messages} signed + verified + forgery-tested in {:?}", t.elapsed());

    // ════════════════════════════════════════
    // Phase 8: Consensus
    // ════════════════════════════════════════
    let t = Instant::now();
    let att_all: Vec<Attestation> = (0..N as u64)
        .map(|id| Attestation { node_id: id, verified: true }).collect();
    assert_eq!(liun_consensus::check_consensus(&att_all, &trust, BFT_THRESHOLD),
        liun_consensus::Decision::Accepted);

    // Minority attestation
    let att_few: Vec<Attestation> = (0..3u64)
        .map(|id| Attestation { node_id: id, verified: true }).collect();
    assert_eq!(liun_consensus::check_consensus(&att_few, &trust, BFT_THRESHOLD),
        liun_consensus::Decision::Pending);

    // All reject
    let att_reject: Vec<Attestation> = (0..N as u64)
        .map(|id| Attestation { node_id: id, verified: false }).collect();
    assert_eq!(liun_consensus::check_consensus(&att_reject, &trust, BFT_THRESHOLD),
        liun_consensus::Decision::Rejected);
    println!("Phase 8: Consensus (accept/pending/reject) in {:?}", t.elapsed());

    // ════════════════════════════════════════
    // Phase 9: Epoch rotation
    // ════════════════════════════════════════
    let t = Instant::now();
    for epoch in 1..=5 {
        committee.rotate(&trust, epoch);
    }
    println!("Phase 9: 5 epoch rotations in {:?}", t.elapsed());

    let total = start.elapsed();
    println!("\n═══════════════════════════════════════════");
    println!("  10-NODE FULL MESH: ALL CLEAR");
    println!("═══════════════════════════════════════════");
    println!("  Nodes:        {N}");
    println!("  Pairwise PSKs: {} (no pre-shared keys)", psks.len());
    println!("  Handshakes:   {handshake_ok}/45 ✓");
    println!("  Exchanges:    {exchange_ok}/45 ✓ ({total_bits} ITS bits)");
    println!("  DKG:          threshold={}, degree={}", dkg_params.threshold, dkg_params.degree);
    println!("  Signatures:   {n_messages} signed + verified + forgery-tested ✓");
    println!("  Consensus:    accept/pending/reject all correct ✓");
    println!("  Committee:    {} members, 5 rotations ✓", committee.size());
    println!("  Total time:   {:?}", total);
    println!("═══════════════════════════════════════════\n");
}
