//! # Scale Test: 50-Node Network
//!
//! Full protocol at scale: bootstrap, pairwise exchanges,
//! DKG, committee selection, threshold signing, verification,
//! rolling committee rotation across multiple epochs.

use liuproto_core::gf61::Gf61;
use liuproto_core::pool::Pool;
use liun_channel::exchange::{ExchangeParams, run_as_alice, run_as_bob};
use liun_overlay::bootstrap::{BootstrapConfig, bootstrap_psk};
use liun_overlay::trust::TrustGraph;
use liun_dkg::{Dkg, DkgParams, Contribution};
use liun_uss::signer::{PartialSigner, combine_signatures};
use liun_uss::verifier::Verifier;
use liun_uss::lagrange;
use liun_uss::shamir::Share;
use liun_consensus::committee::{Committee, CommitteeConfig};
use liun_consensus::{self, Attestation, BFT_THRESHOLD};
use tokio::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::time::Instant;

const N_NODES: usize = 50;
const CHANNELS_PER_NODE: usize = 10; // each node connects to 10 peers
const N_EPOCHS: usize = 5;

#[tokio::test]
async fn test_fifty_node_network() {
    let start = Instant::now();
    println!("\n═══════════════════════════════════════════");
    println!("  {N_NODES}-NODE NETWORK SCALE TEST");
    println!("═══════════════════════════════════════════\n");

    // ════════════════════════════════════════
    // Phase 0: Build trust graph (sparse mesh, not fully connected)
    // ════════════════════════════════════════
    println!("Phase 0: Building trust graph ({N_NODES} nodes, {CHANNELS_PER_NODE} channels each)...");
    let t0 = Instant::now();

    let mut trust_graph = TrustGraph::new();
    let mut channel_pairs: Vec<(usize, usize)> = Vec::new();

    for i in 0..N_NODES {
        for offset in 1..=CHANNELS_PER_NODE {
            let j = (i + offset) % N_NODES;
            if i < j {
                trust_graph.add_channel(i as u64, j as u64, 1.0);
                channel_pairs.push((i, j));
            }
        }
    }
    let n_channels = channel_pairs.len();
    println!("  {n_channels} channels in {:.0}ms", t0.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 1: Bootstrap PSKs for all channel pairs
    // ════════════════════════════════════════
    println!("Phase 1: Bootstrap PSKs...");
    let t1 = Instant::now();

    let config = BootstrapConfig { k: 5, psk_size: 2048 };
    let mut psks: HashMap<(usize, usize), Vec<u8>> = HashMap::new();
    for &(i, j) in &channel_pairs {
        let (psk_a, psk_b) = bootstrap_psk(&config);
        assert_eq!(psk_a, psk_b);
        psks.insert((i, j), psk_a);
    }
    println!("  {n_channels} PSKs in {:.0}ms (no pre-shared keys)", t1.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 2: Liu exchanges on a sample of channels
    // ════════════════════════════════════════
    let sample_size = 20; // test 20 random channel pairs
    println!("Phase 2: Liu exchanges ({sample_size} of {n_channels} channels)...");
    let t2 = Instant::now();

    let batch_size = 500;
    let params = ExchangeParams::new(batch_size, 0.1, 0.5);

    for &(i, j) in channel_pairs.iter().take(sample_size) {
        let psk = psks.get(&(i, j)).unwrap();
        let nonce = [0u8; 16];
        let params_bob = params.clone();
        let params_alice = params.clone();
        let psk_bob = psk.clone();
        let psk_alice = psk.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let bob = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut pool = Pool::from_psk(&psk_bob, &nonce);
            run_as_bob(&mut stream, &mut pool, &params_bob).await.unwrap()
        });

        let alice = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut pool = Pool::from_psk(&psk_alice, &nonce);
            run_as_alice(&mut stream, &mut pool, &params_alice).await.unwrap()
        });

        let ar = alice.await.unwrap();
        let br = bob.await.unwrap();
        assert!(ar.verified && br.verified);
        assert_eq!(ar.sign_bits, br.sign_bits);
    }
    println!("  {sample_size} exchanges verified in {:.0}ms", t2.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 3: Trust computation
    // ════════════════════════════════════════
    println!("Phase 3: Trust computation...");
    let t3 = Instant::now();

    let trust = trust_graph.personalized_pagerank(0, 0.85, 20);
    let total_trust: f64 = trust.values().sum();
    let max_trust = trust.values().cloned().fold(0.0f64, f64::max);
    let min_trust = trust.values().cloned().fold(1.0f64, f64::min);
    println!("  PageRank from node 0: total={total_trust:.3}, max={max_trust:.4}, min={min_trust:.4}");
    println!("  Computed in {:.0}ms", t3.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 4: Committee selection + rolling rotation
    // ════════════════════════════════════════
    println!("Phase 4: Committee selection + {N_EPOCHS} epoch rotations...");
    let t4 = Instant::now();

    let committee_config = CommitteeConfig {
        target_size: 15, // 15 of 50 nodes
        rotation_rate: 0.2, // rotate 20% per epoch
        ..Default::default()
    };
    let mut committee = Committee::new(committee_config);
    committee.initialize(&trust);
    println!("  Initial committee: {} members, threshold={}, budget={}",
        committee.size(), committee.threshold(), committee.signature_budget());

    for epoch in 1..=N_EPOCHS {
        let prev_members = committee.members();
        committee.rotate(&trust, epoch as u64);
        let new_members = committee.members();
        let overlap: usize = prev_members.iter().filter(|id| new_members.contains(id)).count();
        println!("  Epoch {epoch}: {}/{} retained, threshold={}, budget={}",
            overlap, committee.size(), committee.threshold(), committee.signature_budget());
    }
    println!("  {N_EPOCHS} rotations in {:.0}ms", t4.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 5: DKG with committee
    // ════════════════════════════════════════
    println!("Phase 5: DKG with committee...");
    let t5 = Instant::now();

    let committee_ids = committee.members();
    let n_committee = committee_ids.len();
    let dkg_params = DkgParams::new(n_committee);

    let mut contributions: Vec<Contribution> = Vec::new();
    for (idx, _) in committee_ids.iter().enumerate() {
        let secret_bytes = liuproto_core::noise::random_bytes(8);
        let secret = Gf61::random(&secret_bytes.try_into().unwrap());
        contributions.push(Contribution::generate(idx as u64, secret, &dkg_params));
    }

    let mut combined_shares: Vec<Share> = Vec::new();
    for recv in 0..n_committee {
        let mut dkg = Dkg::new(recv, dkg_params.clone());
        for sender in 0..n_committee {
            dkg.receive_share(sender, contributions[sender].share_for(recv));
        }
        combined_shares.push(dkg.combine());
    }

    let xs: Vec<Gf61> = combined_shares.iter().map(|s| s.x).collect();
    let ys: Vec<Gf61> = combined_shares.iter().map(|s| s.y).collect();
    let f0 = lagrange::reconstruct_secret(&xs, &ys);
    println!("  DKG complete: {} members, F(0)={}, in {:.0}ms",
        n_committee, f0, t5.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 6: Sign + verify multiple messages
    // ════════════════════════════════════════
    println!("Phase 6: Threshold signing + verification...");
    let t6 = Instant::now();

    let k = dkg_params.threshold;
    let signer_ids: Vec<u64> = combined_shares[..k].iter().map(|s| s.x.val()).collect();
    let signers: Vec<PartialSigner> = combined_shares[..k].iter()
        .map(|s| PartialSigner::new(s.x.val(), s.y))
        .collect();

    let verifier = Verifier::new(
        combined_shares.iter().map(|s| s.x).collect(),
        combined_shares.iter().map(|s| s.y).collect(),
        dkg_params.degree,
    );

    let n_messages = 10;
    for msg_val in 1..=n_messages {
        let msg = Gf61::new(msg_val as u64 * 1000 + 42);
        let partials: Vec<Gf61> = signers.iter()
            .map(|s| s.partial_sign(msg, &signer_ids))
            .collect();
        let sigma = combine_signatures(&partials);
        assert!(verifier.verify(msg, sigma), "signature verification failed for message {msg_val}");

        // Forgery detection
        let fake = Gf61::new(sigma.val().wrapping_add(1));
        assert!(!verifier.verify(msg, fake), "forgery not detected for message {msg_val}");
    }
    println!("  {n_messages} messages signed + verified + forgery-tested in {:.0}ms",
        t6.elapsed().as_millis());

    // ════════════════════════════════════════
    // Phase 7: Consensus
    // ════════════════════════════════════════
    println!("Phase 7: Consensus...");

    let attestations: Vec<Attestation> = committee_ids.iter()
        .map(|&id| Attestation { node_id: id, verified: true })
        .collect();
    let decision = liun_consensus::check_consensus(&attestations, &trust, BFT_THRESHOLD);
    assert_eq!(decision, liun_consensus::Decision::Accepted);
    println!("  Full attestation: ACCEPTED ✓");

    let total_elapsed = start.elapsed();
    println!("\n═══════════════════════════════════════════");
    println!("  SCALE TEST COMPLETE");
    println!("  Nodes: {N_NODES}");
    println!("  Channels: {n_channels} (sparse mesh, {CHANNELS_PER_NODE}/node)");
    println!("  Liu exchanges: {sample_size} verified over TCP");
    println!("  Committee: {n_committee} members (of {N_NODES}), rolling");
    println!("  Epochs: {N_EPOCHS} rotations");
    println!("  DKG: threshold={}, degree={}", dkg_params.threshold, dkg_params.degree);
    println!("  Signatures: {n_messages} signed + verified + forgery-tested");
    println!("  Consensus: trust-weighted BFT accepted");
    println!("  Pre-shared keys: NONE");
    println!("  Total time: {:.0}ms", total_elapsed.as_millis());
    println!("═══════════════════════════════════════════\n");
}
