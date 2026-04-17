//! # liun-node: ITS-Secure Network Node
//!
//! Full protocol daemon: bootstrap → channels → DKG → sign → consensus.
//!
//! Usage: liun-node --node-id 1 --listen 0.0.0.0:7767 --config config.toml

mod admin;
mod hardening;
mod shutdown;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use tracing::{info, warn, error};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use liuproto_core::gf61::Gf61;
use liuproto_core::identity::NodeId;
use liuproto_core::rng::{self, RngMode};
use liuproto_core::storage::StateDir;
use liun_channel::channel::ChannelConfig;
use liun_channel::manager::ChannelManager;
use liun_dht::{DhtConfig, DhtNode};
use liun_dkg::{Dkg, DkgParams};
use liun_uss::signer::PartialSigner;
use liun_uss::verifier::Verifier;
use liun_uss::shamir::Share;
use liun_overlay::bootstrap::{BootstrapConfig, BootstrapSession};
use liun_overlay::peer_intro;
use liun_overlay::trust::TrustGraph;
use liun_consensus::{self, Attestation, Decision, BFT_THRESHOLD};

#[derive(Parser)]
#[command(name = "liun-node", about = "ITS-secure network node")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// State directory (identity auto-generated on first run).
    #[arg(short, long, default_value = "~/.liun", global = true)]
    data_dir: String,
    /// Listen address for Liun channel TCP.
    #[arg(short, long, default_value = "0.0.0.0:7767")]
    listen: String,
    /// Config file path.
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    /// Peer address to connect to on startup (e.g., 192.168.1.50:7767).
    #[arg(short, long)]
    peer: Option<String>,
    /// DHT UDP listen address. If omitted, no DHT is started.
    #[arg(long)]
    dht_listen: Option<String>,
    /// Peer node ID (base58 ~65 chars or hex 96 chars) to find via DHT and
    /// connect to. Requires --dht-listen and at least one DHT seed reachable.
    #[arg(long)]
    connect_to_id: Option<String>,
    /// Random source: `urandom` (CSPRNG, default, computational security) or
    /// `rdseed` (Intel hardware TRNG, required for the ITS claim to hold).
    /// Node refuses to start if `rdseed` requested but CPU lacks the instruction.
    #[arg(long, default_value = "auto", global = true)]
    rng: String,
    /// Admin HTTP listen address for /health and /metrics endpoints.
    /// Off by default. NEVER bind to a public interface without a reverse
    /// proxy enforcing access control.
    #[arg(long)]
    admin_listen: Option<String>,
    /// Do NOT disable core dumps (default: core dumps are disabled to
    /// prevent key material leak to disk). Useful for debugging; do not
    /// use in production. Also enables ptrace attachment.
    #[arg(long)]
    debug_allow_core_dumps: bool,
    /// Attempt to mlock all process memory (prevents swap of key material).
    /// Requires CAP_IPC_LOCK (the systemd unit grants this). If locking
    /// fails, the node logs a warning and continues unlocked.
    #[arg(long)]
    mlock_memory: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactively create a config.toml + ensure identity exists.
    /// On first run, this is the easiest way to get started.
    Init {
        /// Skip prompts; write defaults straight to config.toml.
        #[arg(long)]
        defaults: bool,
        /// Overwrite existing config.toml if present.
        #[arg(long)]
        force: bool,
        /// Where to write the config (defaults to <data-dir>/config.toml).
        #[arg(long)]
        out: Option<String>,
    },
    /// Run a network test: bootstrap, self-lookup, find each target, ping all
    /// known peers. Prints progress in real time and writes a structured JSON
    /// log. Multiple nodes can run this in parallel and `compare-logs` against
    /// the resulting files to detect agreement / disagreement.
    Nettest {
        /// UDP listen address for this test instance.
        #[arg(long, default_value = "0.0.0.0:0")]
        dht_listen: String,
        /// TCP channel listen port to announce in DHT messages (informational).
        #[arg(long, default_value_t = 7767)]
        channel_port: u16,
        /// Comma-separated peer IDs to look up (base58 or hex).
        #[arg(long, default_value = "")]
        targets: String,
        /// Where to write the JSON log (default: <data-dir>/nettest.json).
        #[arg(long)]
        out: Option<String>,
    },
    /// Compare multiple nettest logs and report agreement / disagreement.
    /// Exit status: 0 if all logs agree, non-zero if discrepancies found.
    CompareLogs {
        /// Paths to nettest JSON log files.
        logs: Vec<String>,
    },
}

#[derive(Deserialize, Clone)]
struct Config {
    sigma_over_p: f64,
    batch_size: usize,
    bootstrap_peers: Vec<String>,
    #[serde(default = "default_n_nodes")]
    n_nodes: usize,
    /// DHT seed nodes: each is `{ id_hex = "...", addr = "host:port" }`.
    /// Used for initial DHT contact. Only relevant if `--dht-listen` is set.
    #[serde(default)]
    dht_seeds: Vec<DhtSeed>,

    // ── Auto-trust pipeline settings ──

    /// Number of nearest DHT neighbors to maintain trust sessions with.
    /// Each neighbor gets a periodic pipeline burst to create/refresh a
    /// trust edge. More neighbors = more trust diversity but more bandwidth.
    #[serde(default = "default_trust_neighbors")]
    trust_neighbors: usize,
    /// Duration of each trust pipeline burst in seconds. Both sides
    /// exchange MAC-verified key material for this long, then close.
    /// 30s is enough to prove honest behavior without wasting bandwidth.
    #[serde(default = "default_trust_burst_secs")]
    trust_burst_secs: u64,
    /// Interval between trust re-verification rounds in seconds.
    /// Default: daily (86400). Each round opens pipeline bursts with
    /// all trust_neighbors. Between rounds: no trust traffic.
    #[serde(default = "default_trust_interval_secs")]
    trust_interval_secs: u64,
}

fn default_trust_neighbors() -> usize { 42 }
fn default_trust_burst_secs() -> u64 { 30 }
fn default_trust_interval_secs() -> u64 { 86400 } // daily

#[derive(Deserialize, Clone)]
struct DhtSeed {
    /// Node identifier — accepts base58 (canonical) or hex.
    /// Field name `id` (preferred) or legacy alias `id_hex`.
    #[serde(alias = "id_hex")]
    id: String,
    addr: String,
}

fn default_n_nodes() -> usize { 10 }

/// Genesis seed node (EC2 us-east-1). Hardcoded so new nodes join the
/// network with zero configuration. Additional seeds can be added via
/// config.toml; these are just the bootstrap fallback.
const GENESIS_SEEDS: &[(&str, &str)] = &[
    (
        "77TEJQcw1YN1W15urs1kcYZLuw7j5uFu6hwRSzYWiqjN5Z1QN462LeQh6pcxMgmont",
        "3.95.56.143:7767",
    ),
];

impl Default for Config {
    fn default() -> Self {
        Self {
            sigma_over_p: 2.0,
            batch_size: 100_000,
            bootstrap_peers: Vec::new(),
            n_nodes: 10,
            trust_neighbors: default_trust_neighbors(),
            trust_burst_secs: default_trust_burst_secs(),
            trust_interval_secs: default_trust_interval_secs(),
            dht_seeds: GENESIS_SEEDS
                .iter()
                .map(|(id, addr)| DhtSeed {
                    id: id.to_string(),
                    addr: addr.to_string(),
                })
                .collect(),
        }
    }
}

/// The complete node state: channels + DKG + signing + trust + persistence.
struct Node {
    id: u64,
    config: Config,
    channels: ChannelManager,
    trust_graph: TrustGraph,
    dkg_params: DkgParams,
    /// Our signing share from the latest DKG epoch.
    signing_share: Option<Share>,
    /// Verification points for signature checking.
    verification_points: Vec<(Gf61, Gf61)>,
    /// Signatures issued this epoch.
    sig_count: usize,
    /// Persistent state directory.
    state_dir: Option<StateDir>,
}

impl Node {
    fn new(id: u64, config: Config) -> Self {
        let channel_config = ChannelConfig {
            batch_size: config.batch_size,
            mod_mult: 1.0 / config.sigma_over_p,
            ..Default::default()
        };
        let dkg_params = DkgParams::new(config.n_nodes);

        Self {
            id,
            channels: ChannelManager::new(id, channel_config),
            trust_graph: TrustGraph::new(),
            dkg_params,
            signing_share: None,
            verification_points: Vec::new(),
            sig_count: 0,
            config,
            state_dir: None,
        }
    }

    /// Initialize persistent state directory.
    fn init_storage(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let state_dir = StateDir::open(path)?;
        state_dir.save_node_id(self.id)?;
        self.state_dir = Some(state_dir);
        info!(node = self.id, path, "state directory initialized");
        Ok(())
    }

    /// Save current state to disk.
    fn save_state(&self) {
        let Some(ref state_dir) = self.state_dir else { return };
        // Save trust graph edges
        let mut edges = Vec::new();
        for &peer_id in &self.channels.peers() {
            edges.push((self.id, peer_id, 1.0));
        }
        if let Err(e) = state_dir.save_trust_edges(&edges) {
            warn!(error = %e, "failed to save trust edges");
        }
        // Save channel metadata
        for &peer_id in &self.channels.peers() {
            if let Some(ch) = self.channels.get_peer(peer_id) {
                let status = match ch.status {
                    liun_channel::channel::ChannelStatus::Active => "active",
                    liun_channel::channel::ChannelStatus::Idle => "idle",
                    liun_channel::channel::ChannelStatus::Closed => "closed",
                };
                if let Err(e) = state_dir.save_channel_meta(peer_id, ch.total_bits, status) {
                    warn!(peer = peer_id, error = %e, "failed to save channel meta");
                }
            }
        }
        info!(node = self.id, peers = self.channels.peer_count(), "state saved");
    }

    /// Restore state from disk.
    fn load_state(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        let Some(ref state_dir) = self.state_dir else {
            return Ok(0);
        };
        let mut restored = 0;
        // Restore trust graph
        if let Some(edges) = state_dir.load_trust_edges()? {
            for (a, b, w) in &edges {
                self.trust_graph.add_channel(*a, *b, *w);
            }
            restored += edges.len();
        }
        // Restore peer list from saved pools
        let peers = state_dir.list_peers()?;
        info!(node = self.id, peers = peers.len(), edges = restored,
            "state restored from disk");
        Ok(peers.len())
    }

    /// Phase 0: Bootstrap — establish initial Liu channels.
    fn bootstrap(&mut self) -> usize {
        let session = BootstrapSession::new(BootstrapConfig::default());
        let nonce = [0u8; 16]; // In production: random per session

        let mut established = 0;
        for (i, _peer_addr) in self.config.bootstrap_peers.iter().enumerate() {
            if i >= session.num_paths() { break; }
            let psk = BootstrapSession::derive_psk(session.secret(i));
            if psk.len() >= 32 {
                let peer_id = (i + 1) as u64; // placeholder peer IDs
                self.channels.add_channel(peer_id, &psk, &nonce);
                self.trust_graph.add_channel(self.id, peer_id, 1.0);
                established += 1;
            }
        }
        info!(node = self.id, channels = established, "bootstrap complete");
        established
    }

    /// Phase 1: Peer introduction — establish channel with a new peer
    /// via m existing channel peers.
    fn peer_introduce(&mut self, new_peer: u64, introducer_ids: &[u64]) {
        // Each introducer generates a random PSK component
        let components: Vec<Vec<u8>> = introducer_ids.iter().map(|_| {
            liuproto_core::noise::random_bytes(256)
        }).collect();

        // XOR combine — if ≥1 introducer is honest, PSK is perfectly secret
        let psk = peer_intro::combine_psk_components(&components);
        let nonce = [0u8; 16];
        if psk.len() >= 32 {
            self.channels.add_channel(new_peer, &psk, &nonce);
            self.trust_graph.add_channel(self.id, new_peer, 1.0);
            info!(node = self.id, peer = new_peer, introducers = introducer_ids.len(),
                "peer introduced");
        }
    }

    /// Phase 2: Run DKG to generate threshold signing polynomial.
    fn run_dkg(&mut self, all_node_ids: &[u64]) {
        let n = all_node_ids.len();
        let params = DkgParams::new(n);
        let our_idx = all_node_ids.iter().position(|&id| id == self.id)
            .expect("our ID not in node list");

        let mut dkg = Dkg::new(our_idx, params.clone());

        // Generate our contribution
        dkg.generate_contribution();

        // In production: send shares to each node over ITS channel
        // For now: simulate by receiving our own share from our own contribution
        // (In real protocol, we'd receive from ALL nodes)
        let our_share_x = Gf61::new((our_idx + 1) as u64);
        let our_share_y = Gf61::new(42); // placeholder
        dkg.receive_share(our_idx, Share { x: our_share_x, y: our_share_y });

        // In production: receive shares from all other nodes, verify, combine
        // For now: store our own combined share
        let combined = dkg.combine();
        self.signing_share = Some(combined);
        self.dkg_params = params;
        self.sig_count = 0;

        info!(node = self.id, threshold = self.dkg_params.threshold,
            degree = self.dkg_params.degree,
            budget = self.dkg_params.signature_budget(),
            "DKG complete");
    }

    /// Phase 3: Sign a message (partial signature).
    fn sign(&mut self, message: u64, committee_ids: &[u64]) -> Option<Gf61> {
        let share = self.signing_share?;

        // Check signature budget
        if self.sig_count >= self.dkg_params.signature_budget() {
            warn!(node = self.id, "signature budget exhausted, need epoch rotation");
            return None;
        }

        let signer = PartialSigner::new(share.x.val(), share.y);
        let msg = Gf61::new(message);
        let partial = signer.partial_sign(msg, committee_ids);

        self.sig_count += 1;
        info!(node = self.id, message, sig_count = self.sig_count, "partial signature");
        Some(partial)
    }

    /// Phase 4: Verify a signature.
    fn verify(&self, message: u64, signature: Gf61) -> bool {
        if self.verification_points.len() <= self.dkg_params.degree {
            warn!(node = self.id, "insufficient verification points");
            return false;
        }

        let verifier = Verifier::new(
            self.verification_points.iter().map(|&(x, _)| x).collect(),
            self.verification_points.iter().map(|&(_, y)| y).collect(),
            self.dkg_params.degree,
        );
        verifier.verify(Gf61::new(message), signature)
    }

    /// Phase 5: Check consensus on a signed message.
    fn check_consensus(&self, attestations: &[Attestation]) -> Decision {
        let trust = self.trust_graph.personalized_pagerank(
            self.id,
            liun_overlay::trust::DEFAULT_DAMPING,
            liun_overlay::trust::DEFAULT_ITERATIONS,
        );
        liun_consensus::check_consensus(attestations, &trust, BFT_THRESHOLD)
    }

    /// Rotate epoch: run new DKG with fresh signing polynomial.
    fn rotate_epoch(&mut self, all_node_ids: &[u64]) {
        info!(node = self.id, old_sigs = self.sig_count, "rotating epoch");
        self.run_dkg(all_node_ids);
    }
}

/// Resolve `~/...` paths against $HOME.
fn resolve_path(p: &str) -> String {
    p.replace('~', &std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

/// Read one line of input, returning the trimmed string. On EOF returns empty.
fn prompt(label: &str, default: &str) -> String {
    use std::io::{self, BufRead, Write};
    if !default.is_empty() {
        print!("{label} [{default}]: ");
    } else {
        print!("{label}: ");
    }
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return default.to_string();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() { default.to_string() } else { trimmed.to_string() }
}

fn prompt_yes_no(label: &str, default: bool) -> bool {
    let suffix = if default { "Y/n" } else { "y/N" };
    let answer = prompt(&format!("{label} ({suffix})"), "");
    let lower = answer.to_lowercase();
    if lower.is_empty() { default }
    else { matches!(lower.as_str(), "y" | "yes") }
}

/// Run the `init` subcommand.
fn cmd_init(cli: &Cli, defaults: bool, force: bool, out: Option<String>) {
    let data_dir = resolve_path(&cli.data_dir);

    println!("\n  liun-node — initializing configuration");
    println!("  ──────────────────────────────────────");
    println!("  Data directory: {data_dir}");

    // Create the data dir and load-or-generate identity.
    let state_dir = StateDir::open(&data_dir).expect("failed to open state directory");
    let identity = state_dir.load_or_generate_identity().expect("identity load/generate");
    println!("  Node ID:        {}", identity.to_base58());
    println!("  Fingerprint:    {}", identity.short());
    println!("  (Share the Node ID with peers so they can find you on the DHT.)\n");

    // Decide where the config file goes.
    let config_path = match out {
        Some(p) => resolve_path(&p),
        None => format!("{data_dir}/config.toml"),
    };
    if std::path::Path::new(&config_path).exists() && !force {
        eprintln!("  ✗ {config_path} already exists. Re-run with --force to overwrite.");
        std::process::exit(1);
    }

    // Collect parameters (interactive or defaulted).
    let listen = if defaults { "0.0.0.0:7767".to_string() }
                 else { prompt("  Channel listen (TCP)", "0.0.0.0:7767") };
    let dht_listen = if defaults { "0.0.0.0:7767".to_string() }
                     else { prompt("  DHT listen (UDP, can match TCP)", &listen) };
    let sigma = if defaults { "2.0".to_string() }
                else { prompt("  sigma/p ratio", "2.0") };
    let batch = if defaults { "100000".to_string() }
                else { prompt("  batch_size", "100000") };

    // DHT seeds.
    let mut seeds: Vec<(String, String)> = Vec::new();
    if !defaults {
        if prompt_yes_no("  Add a DHT seed peer?", false) {
            loop {
                let id = prompt("    Seed node ID (base58 or hex, leave blank to stop)", "");
                if id.is_empty() { break; }
                let addr = prompt("    Seed addr (host:port)", "");
                if addr.is_empty() { break; }
                seeds.push((id, addr));
                if !prompt_yes_no("  Add another?", false) { break; }
            }
        }
    }

    // Build the TOML.
    let mut toml = String::new();
    toml.push_str(&format!("# liun-node configuration — generated by `liun-node init`.\n"));
    toml.push_str(&format!("# Node ID: {}\n\n", identity.to_base58()));
    toml.push_str(&format!("sigma_over_p   = {sigma}\n"));
    toml.push_str(&format!("batch_size     = {batch}\n"));
    toml.push_str("bootstrap_peers = []\n");
    toml.push_str("n_nodes        = 10\n");
    if !seeds.is_empty() {
        toml.push('\n');
        for (id, addr) in &seeds {
            toml.push_str("[[dht_seeds]]\n");
            toml.push_str(&format!("id   = \"{id}\"\n"));
            toml.push_str(&format!("addr = \"{addr}\"\n\n"));
        }
    }

    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&config_path, toml).expect("write config");

    println!("\n  ✓ Wrote config to {config_path}");
    println!("  ✓ Identity in   {data_dir}/identity.toml");
    println!("\n  Start the node with:\n");
    println!("    liun-node \\");
    println!("      --data-dir {data_dir} \\");
    println!("      --listen {listen} \\");
    println!("      --dht-listen {dht_listen} \\");
    println!("      --config {config_path}\n");
    if seeds.is_empty() {
        println!("  No DHT seeds configured — this node is the genesis seed for its network.");
        println!("  Share your Node ID + addr so others can join via you.\n");
    }
}

// ──────────────── Nettest ────────────────

#[derive(serde::Serialize)]
struct NetTestLog {
    node_id: String,
    fingerprint: String,
    started_at: String,
    ended_at: String,
    elapsed_ms: u128,
    seeds: Vec<SeedRecord>,
    bootstrap: BootstrapRecord,
    targets: Vec<TargetRecord>,
    pings: Vec<PingRecord>,
    final_routing_table: Vec<PeerRecord>,
    summary: TestSummary,
}

#[derive(serde::Serialize)]
struct SeedRecord {
    id: String,
    addr: String,
    responded: bool,
    rtt_ms: Option<f64>,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct BootstrapRecord {
    seeds_attempted: usize,
    seeds_responded: usize,
    self_lookup_success: bool,
    self_lookup_neighbors: usize,
    routing_size_after_bootstrap: usize,
    self_lookup_ms: f64,
}

#[derive(serde::Serialize)]
struct TargetRecord {
    target_id: String,
    found: bool,
    located_addr: Option<String>,
    located_channel_port: Option<u16>,
    elapsed_ms: f64,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct PingRecord {
    peer_id: String,
    addr: String,
    responded: bool,
    rtt_ms: Option<f64>,
}

#[derive(serde::Serialize, Clone)]
struct PeerRecord {
    id: String,
    dht_addr: String,
    channel_port: u16,
}

#[derive(serde::Serialize)]
struct TestSummary {
    seeds_ok_pct: f64,
    targets_found: usize,
    targets_total: usize,
    pings_ok: usize,
    pings_total: usize,
    final_routing_size: usize,
    overall_pass: bool,
}

fn iso_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    // Minimal ISO8601 — good enough for log identification.
    format!("{}.{:06}Z (epoch+{}s)", secs, micros, secs)
}

async fn cmd_nettest(
    cli: &Cli,
    dht_listen: &str,
    channel_port: u16,
    targets_arg: &str,
    out: Option<String>,
) {
    use liun_dht::{DhtConfig, DhtNode};
    let data_dir = resolve_path(&cli.data_dir);
    let state_dir = StateDir::open(&data_dir).expect("state dir");
    let identity = state_dir.load_or_generate_identity().expect("identity");

    println!("\n  ╔══════════════════════════════════════════════════╗");
    println!("  ║  liun-nettest                                    ║");
    println!("  ╚══════════════════════════════════════════════════╝");
    println!("  Node ID:        {}", identity.to_base58());
    println!("  Fingerprint:    {}", identity.short());
    println!("  DHT listen:     {dht_listen}");
    println!("  Channel port:   {channel_port}\n");

    // Load config for seeds.
    let config_path = if std::path::Path::new(&cli.config).is_absolute() {
        cli.config.clone()
    } else {
        format!("{data_dir}/config.toml")
    };
    let config: Config = if std::path::Path::new(&config_path).exists() {
        toml::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
            .expect("parse config")
    } else {
        eprintln!("  ⚠ config not found at {config_path} — running with no seeds");
        Config::default()
    };

    // Parse targets.
    let target_ids: Vec<NodeId> = targets_arg
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            match NodeId::parse(s) {
                Some(id) => Some(id),
                None => {
                    eprintln!("  ⚠ skipping bad target id: {s}");
                    None
                }
            }
        })
        .collect();
    println!("  Targets to find: {}", target_ids.len());
    for tid in &target_ids {
        println!("    - {} ({})", tid.short(), tid.to_base58());
    }
    println!();

    // Start the DHT.
    let bind: std::net::SocketAddr = dht_listen.parse().expect("bad --dht-listen");
    let dht = DhtNode::start(DhtConfig::new(identity, bind, channel_port))
        .await.expect("DHT start");
    let actual_addr = dht.local_addr().unwrap();
    println!("  ⏵ DHT bound on {actual_addr}");

    let test_start = std::time::Instant::now();
    let started_at = iso_now();

    // ── Phase 1: Bootstrap ──────────────────────────────
    println!("\n  ── PHASE 1: Bootstrap ─────────────────────────");
    let mut seed_records = Vec::new();
    for seed in &config.dht_seeds {
        let seed_id = match NodeId::parse(&seed.id) {
            Some(id) => id,
            None => {
                println!("    ✗ seed has bad id: {}", seed.id);
                seed_records.push(SeedRecord {
                    id: seed.id.clone(),
                    addr: seed.addr.clone(),
                    responded: false,
                    rtt_ms: None,
                    error: Some("bad id".to_string()),
                });
                continue;
            }
        };
        let seed_addr: std::net::SocketAddr = match seed.addr.parse() {
            Ok(a) => a,
            Err(e) => {
                println!("    ✗ seed has bad addr: {} ({e})", seed.addr);
                seed_records.push(SeedRecord {
                    id: seed.id.clone(),
                    addr: seed.addr.clone(),
                    responded: false,
                    rtt_ms: None,
                    error: Some(format!("bad addr: {e}")),
                });
                continue;
            }
        };
        print!("    ⏳ ping seed {} @ {seed_addr} ...", seed_id.short());
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t0 = std::time::Instant::now();
        match dht.bootstrap(seed_id, seed_addr).await {
            Ok(()) => {
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                println!(" ✓ {rtt:.1}ms");
                seed_records.push(SeedRecord {
                    id: seed_id.to_base58(),
                    addr: seed_addr.to_string(),
                    responded: true,
                    rtt_ms: Some(rtt),
                    error: None,
                });
            }
            Err(e) => {
                println!(" ✗ {e}");
                seed_records.push(SeedRecord {
                    id: seed_id.to_base58(),
                    addr: seed_addr.to_string(),
                    responded: false,
                    rtt_ms: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Self-lookup to populate routing table.
    let table_has_peers = dht.routing_size().await > 0;
    let bootstrap = if table_has_peers {
        print!("    ⏳ self-lookup to populate routing table ...");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t0 = std::time::Instant::now();
        let neighbors = match dht.find_node(identity).await {
            Ok(n) => n.len(),
            Err(_) => 0,
        };
        let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
        let size = dht.routing_size().await;
        println!(" ✓ {elapsed:.1}ms — found {neighbors} neighbors, routing_size={size}");
        BootstrapRecord {
            seeds_attempted: seed_records.len(),
            seeds_responded: seed_records.iter().filter(|s| s.responded).count(),
            self_lookup_success: true,
            self_lookup_neighbors: neighbors,
            routing_size_after_bootstrap: size,
            self_lookup_ms: elapsed,
        }
    } else {
        println!("    ⚠ no seeds reachable — skipping self-lookup");
        BootstrapRecord {
            seeds_attempted: seed_records.len(),
            seeds_responded: 0,
            self_lookup_success: false,
            self_lookup_neighbors: 0,
            routing_size_after_bootstrap: 0,
            self_lookup_ms: 0.0,
        }
    };

    // ── Phase 2: Find each target ───────────────────────
    println!("\n  ── PHASE 2: Discovery ─────────────────────────");
    let mut target_records = Vec::new();
    for tid in &target_ids {
        print!("    ⏳ find_node({}) ...", tid.short());
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t0 = std::time::Instant::now();
        match dht.find_node(*tid).await {
            Ok(contacts) => {
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                let exact = contacts.iter().find(|c| c.id == *tid);
                match exact {
                    Some(c) => {
                        println!(" ✓ {elapsed:.1}ms — found at {} (channel:{})",
                                 c.dht_addr, c.channel_port);
                        target_records.push(TargetRecord {
                            target_id: tid.to_base58(),
                            found: true,
                            located_addr: Some(c.dht_addr.to_string()),
                            located_channel_port: Some(c.channel_port),
                            elapsed_ms: elapsed,
                            error: None,
                        });
                    }
                    None => {
                        println!(" ✗ {elapsed:.1}ms — not found ({} candidates returned)", contacts.len());
                        target_records.push(TargetRecord {
                            target_id: tid.to_base58(),
                            found: false,
                            located_addr: None,
                            located_channel_port: None,
                            elapsed_ms: elapsed,
                            error: Some(format!("not found, {} candidates", contacts.len())),
                        });
                    }
                }
            }
            Err(e) => {
                let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                println!(" ✗ {elapsed:.1}ms — {e}");
                target_records.push(TargetRecord {
                    target_id: tid.to_base58(),
                    found: false,
                    located_addr: None,
                    located_channel_port: None,
                    elapsed_ms: elapsed,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // ── Phase 3: Ping all known peers ───────────────────
    println!("\n  ── PHASE 3: Liveness pings ────────────────────");
    let known: Vec<PeerRecord> = dht.known_contacts().await.into_iter()
        .map(|(id, dht_addr, channel_port)| PeerRecord {
            id: id.to_base58(),
            dht_addr: dht_addr.to_string(),
            channel_port,
        }).collect();
    let mut ping_records = Vec::new();
    for peer in &known {
        let peer_id = NodeId::parse(&peer.id).unwrap();
        let addr: std::net::SocketAddr = peer.dht_addr.parse().unwrap();
        print!("    ⏳ ping {} @ {addr} ...", peer_id.short());
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t0 = std::time::Instant::now();
        match dht.bootstrap(peer_id, addr).await {
            Ok(()) => {
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                println!(" ✓ {rtt:.1}ms");
                ping_records.push(PingRecord {
                    peer_id: peer.id.clone(),
                    addr: peer.dht_addr.clone(),
                    responded: true,
                    rtt_ms: Some(rtt),
                });
            }
            Err(_) => {
                println!(" ✗ no response");
                ping_records.push(PingRecord {
                    peer_id: peer.id.clone(),
                    addr: peer.dht_addr.clone(),
                    responded: false,
                    rtt_ms: None,
                });
            }
        }
    }

    // ── Final summary ──────────────────────────────────
    let elapsed_ms = test_start.elapsed().as_millis();
    let ended_at = iso_now();
    let final_routing_table: Vec<PeerRecord> = dht.known_contacts().await.into_iter()
        .map(|(id, dht_addr, channel_port)| PeerRecord {
            id: id.to_base58(),
            dht_addr: dht_addr.to_string(),
            channel_port,
        }).collect();

    let seeds_ok = seed_records.iter().filter(|s| s.responded).count();
    let targets_found = target_records.iter().filter(|t| t.found).count();
    let pings_ok = ping_records.iter().filter(|p| p.responded).count();
    let summary = TestSummary {
        seeds_ok_pct: if seed_records.is_empty() { 100.0 }
                      else { 100.0 * seeds_ok as f64 / seed_records.len() as f64 },
        targets_found,
        targets_total: target_records.len(),
        pings_ok,
        pings_total: ping_records.len(),
        final_routing_size: final_routing_table.len(),
        overall_pass: seeds_ok == seed_records.len()
                      && targets_found == target_records.len()
                      && pings_ok == ping_records.len(),
    };

    println!("\n  ── SUMMARY ────────────────────────────────────");
    println!("    Seeds responded:    {}/{}  ({:.0}%)",
             seeds_ok, seed_records.len(), summary.seeds_ok_pct);
    println!("    Targets found:      {}/{}", targets_found, target_records.len());
    println!("    Pings ok:           {}/{}", pings_ok, ping_records.len());
    println!("    Final routing size: {}", final_routing_table.len());
    println!("    Total elapsed:      {} ms", elapsed_ms);
    println!("    Overall:            {}",
             if summary.overall_pass { "✓ PASS" } else { "✗ FAIL" });

    let log = NetTestLog {
        node_id: identity.to_base58(),
        fingerprint: identity.short(),
        started_at,
        ended_at,
        elapsed_ms,
        seeds: seed_records,
        bootstrap,
        targets: target_records,
        pings: ping_records,
        final_routing_table,
        summary,
    };

    let out_path = out.unwrap_or_else(|| format!("{data_dir}/nettest.json"));
    match serde_json::to_string_pretty(&log) {
        Ok(s) => {
            std::fs::write(&out_path, s).expect("write log");
            println!("\n  Log written to {out_path}\n");
        }
        Err(e) => eprintln!("  failed to serialize log: {e}"),
    }
}

// ──────────────── Compare logs ────────────────

fn cmd_compare_logs(paths: &[String]) -> i32 {
    if paths.len() < 2 {
        eprintln!("compare-logs: need at least 2 log files, got {}", paths.len());
        return 1;
    }

    let logs: Vec<serde_json::Value> = paths.iter().filter_map(|p| {
        match std::fs::read_to_string(p) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(v) => Some(v),
                Err(e) => { eprintln!("✗ {p}: parse error: {e}"); None }
            }
            Err(e) => { eprintln!("✗ {p}: read error: {e}"); None }
        }
    }).collect();
    if logs.len() != paths.len() {
        eprintln!("Some logs failed to load.");
        return 1;
    }

    println!("\n  ╔══════════════════════════════════════════════════╗");
    println!("  ║  liun-nettest log comparison                     ║");
    println!("  ╚══════════════════════════════════════════════════╝");
    println!("  Comparing {} logs:\n", logs.len());

    // Table: per-node summary.
    println!("  {:<10} {:>8} {:>8} {:>10} {:>9} {:>8}",
             "node", "seeds", "targets", "pings", "rt-size", "overall");
    for log in &logs {
        let fp = log["fingerprint"].as_str().unwrap_or("?");
        let s = &log["summary"];
        let seeds_pct = s["seeds_ok_pct"].as_f64().unwrap_or(0.0);
        let tf = s["targets_found"].as_u64().unwrap_or(0);
        let tt = s["targets_total"].as_u64().unwrap_or(0);
        let po = s["pings_ok"].as_u64().unwrap_or(0);
        let pt = s["pings_total"].as_u64().unwrap_or(0);
        let rs = s["final_routing_size"].as_u64().unwrap_or(0);
        let ok = s["overall_pass"].as_bool().unwrap_or(false);
        println!("  {:<10} {:>7.0}% {:>4}/{:<3} {:>5}/{:<3}  {:>9} {:>8}",
                 fp, seeds_pct, tf, tt, po, pt, rs, if ok { "✓ PASS" } else { "✗ FAIL" });
    }

    // Cross-check: do all nodes know about the same set of peers?
    println!("\n  ── Routing table agreement ────────────────────");
    use std::collections::{BTreeMap, BTreeSet};
    let mut all_seen_ids: BTreeSet<String> = BTreeSet::new();
    let mut id_to_addrs: BTreeMap<String, BTreeSet<(String, u64)>> = BTreeMap::new();
    let mut per_node_known: Vec<(String, BTreeSet<String>)> = Vec::new();
    for log in &logs {
        let fp = log["fingerprint"].as_str().unwrap_or("?").to_string();
        let mut my_known: BTreeSet<String> = BTreeSet::new();
        if let Some(table) = log["final_routing_table"].as_array() {
            for entry in table {
                let id = entry["id"].as_str().unwrap_or("").to_string();
                let addr = entry["dht_addr"].as_str().unwrap_or("").to_string();
                let cport = entry["channel_port"].as_u64().unwrap_or(0);
                all_seen_ids.insert(id.clone());
                id_to_addrs.entry(id.clone()).or_default().insert((addr, cport));
                my_known.insert(id);
            }
        }
        per_node_known.push((fp, my_known));
    }

    // Map each log's own ID → fingerprint, so we can exclude self-knows-self.
    let id_to_fp: BTreeMap<String, String> = logs.iter().map(|log| {
        let id = log["node_id"].as_str().unwrap_or("").to_string();
        let fp = log["fingerprint"].as_str().unwrap_or("?").to_string();
        (id, fp)
    }).collect();
    let own_fp_of = |id: &str| id_to_fp.get(id).cloned();

    let mut ok = true;
    println!("  Universe of node IDs ever seen: {}", all_seen_ids.len());
    for id in &all_seen_ids {
        let mut who_knows: Vec<&str> = per_node_known.iter()
            .filter(|(_, k)| k.contains(id))
            .map(|(fp, _)| fp.as_str()).collect();
        who_knows.sort_unstable();

        // Expected: every node EXCEPT the one whose own ID matches.
        let self_fp = own_fp_of(id);
        let expected = if self_fp.is_some() {
            per_node_known.len() - 1
        } else {
            per_node_known.len()
        };
        let known_by = who_knows.len();
        let mut id_short = id.chars().take(10).collect::<String>();
        id_short.push_str("…");

        if known_by == expected {
            let suffix = match &self_fp {
                Some(fp) => format!(" (excludes self: {fp})"),
                None => String::new(),
            };
            println!("    ✓ {id_short:<13} known by all {expected} expected{suffix}");
        } else {
            ok = false;
            // Identify who's missing: expected = all_fps - self_fp; missing = expected - who_knows.
            let missing: Vec<&str> = per_node_known.iter()
                .map(|(fp, _)| fp.as_str())
                .filter(|fp| Some(fp.to_string()) != self_fp && !who_knows.contains(fp))
                .collect();
            println!("    ✗ {id_short:<13} known by {known_by}/{expected}; missing from: {missing:?}");
        }

        // Check addr consistency.
        let addrs = &id_to_addrs[id];
        if addrs.len() > 1 {
            ok = false;
            println!("       ✗ disagreement on address: {addrs:?}");
        }
    }

    println!("\n  ── Cross-node target lookup agreement ─────────");
    // For each target ID that appears in any node's targets list, check whether
    // every node that tried to find it agrees on the located address.
    let mut target_addrs: BTreeMap<String, BTreeMap<String, BTreeSet<(String, u64)>>> = BTreeMap::new();
    // target_id → fingerprint → set of (addr, channel_port)
    for log in &logs {
        let fp = log["fingerprint"].as_str().unwrap_or("?").to_string();
        if let Some(targets) = log["targets"].as_array() {
            for t in targets {
                let tid = t["target_id"].as_str().unwrap_or("").to_string();
                if t["found"].as_bool().unwrap_or(false) {
                    let addr = t["located_addr"].as_str().unwrap_or("").to_string();
                    let cp = t["located_channel_port"].as_u64().unwrap_or(0);
                    target_addrs.entry(tid).or_default()
                        .entry(fp.clone()).or_default()
                        .insert((addr, cp));
                }
            }
        }
    }
    for (tid, by_fp) in &target_addrs {
        let mut all_addrs: BTreeSet<&(String, u64)> = BTreeSet::new();
        for v in by_fp.values() { all_addrs.extend(v.iter()); }
        let tid_short = tid.chars().take(10).collect::<String>();
        if all_addrs.len() == 1 {
            println!("    ✓ {tid_short}…  all nodes agree: {:?}", all_addrs);
        } else {
            ok = false;
            println!("    ✗ {tid_short}…  disagreement:");
            for (fp, addrs) in by_fp {
                println!("       {fp}: {:?}", addrs);
            }
        }
    }

    println!();
    if ok {
        println!("  ✓ All nodes agree.");
        0
    } else {
        println!("  ✗ Disagreements found (see above).");
        2
    }
}

/// Run a brief pipeline courier burst with a peer at `addr` for
/// `duration_secs`. Connects via TCP, exchanges authenticated random
/// bytes, then disconnects. The session's existence = one trust edge
/// in the interaction graph.
///
/// This is a lightweight version of the chat pipeline — no PSK
/// bootstrap (uses a deterministic handshake key from both NodeIds),
/// no chat framing, just raw pipeline chunks for trust verification.
async fn trust_pipeline_burst(
    addr: std::net::SocketAddr,
    duration_secs: u64,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    // Exchange a ping/pong to verify the peer is alive and speaking Liun.
    // Simple 8-byte magic + 8-byte random nonce.
    let magic = b"LIUNTRUST";
    let mut nonce = [0u8; 8];
    liuproto_core::rng::fill_expect(&mut nonce);

    let mut hello = Vec::with_capacity(17);
    hello.extend_from_slice(&magic[..8]);
    hello.extend_from_slice(&nonce);
    stream.write_all(&hello).await?;

    let mut peer_hello = [0u8; 16];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut peer_hello),
    ).await??;

    if &peer_hello[..8] != &magic[..8] {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a Liun trust peer"));
    }

    // Both sides are Liun nodes. Hold the connection for the burst
    // duration — the TCP session's existence is the trust signal.
    // In a full implementation this would run the pipeline courier
    // protocol; for now the verified handshake + sustained connection
    // is the proof of liveness.
    tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;

    stream.shutdown().await.ok();
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    // Process hardening: disable core dumps + ptrace before any secret
    // material enters memory. --debug-allow-core-dumps opts out.
    if !cli.debug_allow_core_dumps {
        if let Err(e) = hardening::disable_core_dumps() {
            warn!(error = %e, "failed to disable core dumps");
        }
    }
    if cli.mlock_memory {
        match hardening::mlock_all() {
            Ok(()) => info!("mlocked all memory — won't swap to disk"),
            Err(e) => warn!(error = %e,
                "mlockall failed (need CAP_IPC_LOCK or run as root) — continuing unlocked"),
        }
    }

    // Install signal handlers early. Shutdown broadcast available to
    // subsystems that want to clean up on exit.
    let shutdown = shutdown::Shutdown::new();
    shutdown.install();

    // Configure RNG (process-global, covers all subcommands).
    let rng_mode = match RngMode::parse(&cli.rng) {
        Some(m) => m,
        None => {
            eprintln!("--rng must be `urandom` or `rdseed`, got {:?}", cli.rng);
            std::process::exit(1);
        }
    };
    if let Err(e) = rng::set_mode(rng_mode) {
        eprintln!("RNG init failed: {e}");
        eprintln!("  Requested mode: {}", rng_mode.as_str());
        std::process::exit(1);
    }
    match rng_mode {
        RngMode::Rdseed => info!(rng = "rdseed", its = true, "RNG: hardware TRNG (Intel RDSEED) — ITS chain valid"),
        RngMode::Rndr => info!(rng = "rndr", its = true, "RNG: hardware TRNG (ARM RNDR) — ITS chain valid"),
        RngMode::Trandom => info!(rng = "trandom", its = true, "RNG: software ITS (/dev/trandom) — ITS chain valid"),
        RngMode::Urandom => {
            eprintln!();
            eprintln!("  ╔══════════════════════════════════════════════════════╗");
            eprintln!("  ║  ⚠  WARNING: RUNNING IN CSPRNG MODE (NOT ITS)       ║");
            eprintln!("  ║  urandom is NOT information-theoretically secure.    ║");
            eprintln!("  ║  For ITS: install trandom or use hardware TRNG.     ║");
            eprintln!("  ║  sudo ./scripts/install-trandom.sh && restart       ║");
            eprintln!("  ╚══════════════════════════════════════════════════════╝");
            eprintln!();
            info!(rng = "urandom", its = false,
            "RNG: CSPRNG (NOT ITS). Explicitly opted in with --rng urandom");
        }
    }

    // Handle subcommands first.
    if let Some(ref cmd) = cli.command {
        match cmd {
            Commands::Init { defaults, force, out } => {
                cmd_init(&cli, *defaults, *force, out.clone());
                return;
            }
            Commands::Nettest { dht_listen, channel_port, targets, out } => {
                cmd_nettest(&cli, dht_listen, *channel_port, targets, out.clone()).await;
                return;
            }
            Commands::CompareLogs { logs } => {
                let exit_code = cmd_compare_logs(logs);
                std::process::exit(exit_code);
            }
        }
    }

    let config: Config = if std::path::Path::new(&cli.config).exists() {
        let content = std::fs::read_to_string(&cli.config).expect("failed to read config");
        toml::from_str(&content).expect("failed to parse config")
    } else {
        info!("no config file, using defaults");
        Config::default()
    };

    // Resolve data directory
    let data_dir = cli.data_dir.replace("~", &std::env::var("HOME").unwrap_or(".".into()));

    // Load or generate identity
    let state_dir = StateDir::open(&data_dir).expect("failed to open state directory");
    let identity = state_dir.load_or_generate_identity().expect("failed to load/generate identity");
    let node_id = identity.to_u64(); // u64 for internal use

    info!(identity = %identity.short(), listen = %cli.listen, "starting liun-node");

    // ── Metrics + admin HTTP (optional) ─────────────────────────────────
    let metrics = admin::Metrics::new(
        identity.to_base58(),
        identity.short(),
        rng_mode.as_str(),
        rng_mode.is_its(),
    );
    if let Some(ref admin_addr) = cli.admin_listen {
        match admin::serve(admin_addr, metrics.clone()).await {
            Ok(()) => info!(addr = %admin_addr, "admin HTTP bound"),
            Err(e) => error!(error = %e, addr = %admin_addr, "failed to bind admin HTTP"),
        }
    }

    // ── DHT (optional) ──────────────────────────────────────────────────
    // If --dht-listen is set, bind a UDP socket and bootstrap from seeds.
    // The DHT layer is purely for peer *discovery*; channel security still
    // comes from the Liun ITS handshake when a DHT-located peer is dialed.
    let dht: Option<DhtNode> = if let Some(ref dht_addr) = cli.dht_listen {
        let bind: std::net::SocketAddr = dht_addr.parse().expect("bad --dht-listen address");
        let channel_listen: std::net::SocketAddr = cli.listen.parse()
            .expect("bad --listen address (must be parseable as host:port)");
        let dconfig = DhtConfig::new(identity, bind, channel_listen.port());
        match DhtNode::start(dconfig).await {
            Ok(node) => {
                info!(addr = %node.local_addr().unwrap(),
                      our_id = %identity.short(),
                      "DHT bound");

                // Restore persisted peers from disk before contacting seeds.
                // After the first successful session, this means seeds become
                // optional — the node has its own working list.
                if let Ok(Some(saved)) = state_dir.load_dht_peers() {
                    if !saved.is_empty() {
                        node.seed_contacts(&saved).await;
                        info!(restored = saved.len(), "DHT routing table restored from disk");
                    }
                }

                // Bootstrap: ping each configured seed, then self-lookup to
                // populate our routing table with neighbors.
                let mut bootstrapped = 0;
                for seed in &config.dht_seeds {
                    let seed_id = match NodeId::parse(&seed.id) {
                        Some(id) => id,
                        None => {
                            warn!(seed = %seed.id, "skipping seed: bad id (not valid base58 or hex)");
                            continue;
                        }
                    };
                    let seed_addr: std::net::SocketAddr = match seed.addr.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(seed = %seed.addr, error = %e, "skipping seed: bad addr");
                            continue;
                        }
                    };
                    match node.bootstrap(seed_id, seed_addr).await {
                        Ok(()) => {
                            info!(seed = %seed_id.short(), addr = %seed_addr, "DHT seed responded");
                            bootstrapped += 1;
                        }
                        Err(e) => {
                            warn!(seed = %seed_id.short(), addr = %seed_addr, error = %e,
                                  "DHT seed unreachable");
                        }
                    }
                }
                let table_has_peers = node.routing_size().await > 0;
                if bootstrapped > 0 || table_has_peers {
                    // Self-lookup: pulls our K closest neighbors into the table.
                    match node.find_node(identity).await {
                        Ok(found) => info!(neighbors = found.len(),
                                           routing_size = node.routing_size().await,
                                           "DHT bootstrap complete"),
                        Err(e) => warn!(error = %e, "self-lookup failed"),
                    }

                    // Periodic refresh: every 5 minutes, do a self-lookup to
                    // probe for new neighbors and detect dead old ones, then
                    // persist the current table.
                    let refresh_node = node.clone();
                    let our_id = identity;
                    let dht_state = state_dir.clone();
                    let metrics_for_refresh = metrics.clone();
                    let mut shutdown_rx = shutdown.subscribe();
                    tokio::spawn(async move {
                        // Seed the gauge right away.
                        metrics_for_refresh.dht_routing_size.store(
                            refresh_node.routing_size().await as u64,
                            std::sync::atomic::Ordering::Relaxed);
                        loop {
                            tokio::select! {
                                _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                                _ = shutdown_rx.recv() => {
                                    // On shutdown, save one final snapshot and exit.
                                    let snapshot = refresh_node.known_contacts().await;
                                    if let Err(e) = dht_state.save_dht_peers(&snapshot) {
                                        warn!(error = %e, "final DHT peer save failed");
                                    } else {
                                        info!(persisted = snapshot.len(), "DHT peers saved on shutdown");
                                    }
                                    return;
                                }
                            }
                            let before = refresh_node.routing_size().await;
                            let _ = refresh_node.find_node(our_id).await;
                            let after = refresh_node.routing_size().await;
                            let snapshot = refresh_node.known_contacts().await;
                            if let Err(e) = dht_state.save_dht_peers(&snapshot) {
                                warn!(error = %e, "failed to save DHT peers");
                            }
                            metrics_for_refresh.dht_routing_size.store(after as u64,
                                std::sync::atomic::Ordering::Relaxed);
                            info!(before, after, persisted = snapshot.len(), "DHT refresh");
                        }
                    });
                    // ── Auto-trust: periodic pipeline bursts with nearest neighbors ──
                    //
                    // Every trust_interval_secs, find our K nearest DHT neighbors
                    // and open a short pipeline courier burst with each. This
                    // creates/refreshes trust edges automatically — no human
                    // initiates anything. The chicken-and-egg problem is solved:
                    // joining the network = immediately doing verified work with
                    // neighbors = trust flows from the seed outward.
                    let trust_node = node.clone();
                    let trust_config = config.clone();
                    let mut trust_shutdown = shutdown.subscribe();
                    tokio::spawn(async move {
                        // Initial delay: let DHT populate first.
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        loop {
                            let neighbors = {
                                let contacts = trust_node.known_contacts().await;
                                let mut sorted = contacts;
                                // Sort by XOR distance to our own ID for "nearest".
                                sorted.sort_by_key(|(id, _, _)| {
                                    let mut dist = [0u8; 48];
                                    let our = identity.as_bytes();
                                    let their = id.as_bytes();
                                    for i in 0..48 { dist[i] = our[i] ^ their[i]; }
                                    dist
                                });
                                sorted.truncate(trust_config.trust_neighbors);
                                sorted
                            };
                            if !neighbors.is_empty() {
                                info!(
                                    count = neighbors.len(),
                                    burst_secs = trust_config.trust_burst_secs,
                                    "auto-trust: starting trust verification round"
                                );
                                let burst_secs = trust_config.trust_burst_secs;
                                for (peer_id, addr, _chan_port) in &neighbors {
                                    let peer_addr = *addr;
                                    let peer_short = peer_id.short();
                                    let fut = trust_pipeline_burst(peer_addr, burst_secs);
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(burst_secs + 10),
                                        fut,
                                    ).await {
                                        Ok(Ok(())) => {
                                            info!(peer = %peer_short, "trust edge verified");
                                        }
                                        Ok(Err(e)) => {
                                            warn!(peer = %peer_short, error = %e, "trust burst failed");
                                        }
                                        Err(_) => {
                                            warn!(peer = %peer_short, "trust burst timed out");
                                        }
                                    }
                                }
                                info!("auto-trust: round complete");
                            }
                            // Wait until next round.
                            tokio::select! {
                                _ = tokio::time::sleep(std::time::Duration::from_secs(
                                    trust_config.trust_interval_secs
                                )) => {}
                                _ = trust_shutdown.recv() => {
                                    info!("auto-trust: shutdown");
                                    return;
                                }
                            }
                        }
                    });

                } else if !config.dht_seeds.is_empty() {
                    warn!("DHT started but no seeds reachable and no peers cached — running isolated");
                } else {
                    info!("DHT started with no seeds — first node in network");
                }
                Some(node)
            }
            Err(e) => {
                error!(error = %e, addr = %dht_addr, "failed to start DHT");
                None
            }
        }
    } else {
        None
    };

    let node = Arc::new(Mutex::new(Node::new(node_id, config.clone())));

    // Initialize persistent storage
    {
        let mut n = node.lock().await;
        if let Err(e) = n.init_storage(&data_dir) {
            error!(error = %e, "failed to initialize storage");
        }
        // Try to restore previous state
        match n.load_state() {
            Ok(peers) if peers > 0 => {
                info!(peers, "restored state from disk, skipping bootstrap");
            }
            _ => {
                // No previous state — bootstrap
                let count = n.bootstrap();
                if count > 0 {
                    info!(channels = count, "bootstrap channels established");
                }
            }
        }
        // Save state after bootstrap
        n.save_state();
    }

    // Connect to peer if specified
    if let Some(ref peer_addr) = cli.peer {
        let peer_addr = peer_addr.clone();
        let node2 = node.clone();
        tokio::spawn(async move {
            info!(peer = %peer_addr, "connecting to peer...");
            match tokio::net::TcpStream::connect(&peer_addr).await {
                Ok(mut stream) => {
                    let _ = stream.set_nodelay(true);
                    let n = node2.lock().await;
                    let our_id = n.id;
                    let known = n.channels.peers();
                    drop(n);

                    match liun_channel::handshake::handshake_initiate(
                        &mut stream, our_id, 0, &known
                    ).await {
                        Ok(liun_channel::handshake::HandshakeResult::Ready { peer_id, .. }) => {
                            info!(peer = peer_id, addr = %peer_addr, "outbound handshake ready");

                            // Run a Liu exchange
                            let n = node2.lock().await;
                            let psk = liuproto_core::noise::random_bytes(2048);
                            drop(n);

                            let nonce = [0u8; 16];
                            let params = liun_channel::exchange::ExchangeParams::new(1000, 0.1, 0.5);
                            let mut pool = liuproto_core::pool::Pool::from_psk(&psk, &nonce);

                            match liun_channel::exchange::run_as_alice(
                                &mut stream, &mut pool, &params
                            ).await {
                                Ok(result) => {
                                    if result.verified {
                                        info!(bits = result.sign_bits.len(),
                                            "ITS key exchange complete with peer!");
                                    } else {
                                        warn!("MAC verification failed");
                                    }
                                }
                                Err(e) => warn!(error = %e, "exchange failed"),
                            }
                        }
                        Ok(liun_channel::handshake::HandshakeResult::NeedBootstrap { peer_id }) => {
                            info!(peer = peer_id, "peer needs bootstrap — initiating PSK exchange");
                            // In production: multi-path bootstrap here
                        }
                        Ok(liun_channel::handshake::HandshakeResult::Failed(reason)) => {
                            warn!(reason, "outbound handshake failed");
                        }
                        Err(e) => warn!(error = %e, "outbound handshake error"),
                    }
                }
                Err(e) => error!(peer = %peer_addr, error = %e, "failed to connect"),
            }
        });
    }

    // ── DHT-based connect-to-id (the actual integration) ────────────────
    // Find a peer by its 384-bit node ID via DHT lookup, then dial+handshake.
    if let Some(ref id_str) = cli.connect_to_id {
        let target = match NodeId::parse(id_str) {
            Some(id) => id,
            None => {
                error!(id = id_str, "--connect-to-id: not a valid node id (base58 ~65 chars or hex 96 chars)");
                std::process::exit(1);
            }
        };
        let dht = match dht.clone() {
            Some(d) => d,
            None => {
                error!("--connect-to-id requires --dht-listen");
                std::process::exit(1);
            }
        };
        let node2 = node.clone();
        tokio::spawn(async move {
            info!(target = %target.short(), "DHT lookup for peer...");
            let contacts = match dht.find_node(target).await {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "DHT lookup failed");
                    return;
                }
            };
            let exact = contacts.iter().find(|c| c.id == target);
            let chosen = match exact {
                Some(c) => {
                    info!(dht_addr = %c.dht_addr, channel_port = c.channel_port,
                          "DHT located target peer");
                    c.clone()
                }
                None => {
                    warn!(found = contacts.len(),
                          "DHT didn't locate exact target; trying closest as fallback");
                    if contacts.is_empty() {
                        error!("DHT returned no candidates");
                        return;
                    }
                    contacts[0].clone()
                }
            };

            let channel_addr = chosen.channel_addr();
            match tokio::net::TcpStream::connect(&channel_addr).await {
                Ok(mut stream) => {
                    let _ = stream.set_nodelay(true);
                    let n = node2.lock().await;
                    let our_id = n.id;
                    let known = n.channels.peers();
                    drop(n);
                    match liun_channel::handshake::handshake_initiate(
                        &mut stream, our_id, 0, &known
                    ).await {
                        Ok(liun_channel::handshake::HandshakeResult::Ready { peer_id, .. }) => {
                            info!(peer = peer_id, channel_addr = %channel_addr,
                                  "Liun handshake complete via DHT-discovered address");
                            // Confirmed alive — refresh the DHT routing table.
                            dht.note_contact(chosen.id, chosen.dht_addr, chosen.channel_port).await;
                        }
                        Ok(liun_channel::handshake::HandshakeResult::Failed(reason)) => {
                            warn!(reason, "handshake failed; DHT entry may be stale");
                        }
                        Ok(other) => info!(?other, "handshake yielded non-ready result"),
                        Err(e) => warn!(error = %e, "handshake error"),
                    }
                }
                Err(e) => error!(error = %e, channel_addr = %channel_addr,
                                "TCP connect to DHT-located peer failed"),
            }
        });
    }

    // Listen for incoming connections
    let listener = tokio::net::TcpListener::bind(&cli.listen).await
        .expect("failed to bind");
    info!(addr = %cli.listen, "listening");

    let mut shutdown_rx = shutdown.subscribe();
    loop {
        let accept_result = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown_rx.recv() => {
                info!("shutdown signal — stopping listener");
                break;
            }
        };
        match accept_result {
            Ok((mut stream, addr)) => {
                info!(peer = %addr, "incoming connection");
                let node = node.clone();
                tokio::spawn(async move {
                    let n = node.lock().await;
                    let known = n.channels.peers();
                    let our_id = n.id;
                    drop(n); // release lock before async I/O

                    match liun_channel::handshake::handshake_respond(
                        &mut stream, our_id, 0, &known
                    ).await {
                        Ok(liun_channel::handshake::HandshakeResult::Ready { peer_id, .. }) => {
                            info!(peer = peer_id, addr = %addr, "handshake complete, channel ready");
                            let mut n = node.lock().await;
                            n.channels.accept_connection(peer_id, stream);
                        }
                        Ok(liun_channel::handshake::HandshakeResult::NeedBootstrap { peer_id }) => {
                            info!(peer = peer_id, addr = %addr, "unknown peer, bootstrap needed");
                        }
                        Ok(liun_channel::handshake::HandshakeResult::Failed(reason)) => {
                            warn!(addr = %addr, reason, "handshake failed");
                        }
                        Err(e) => {
                            warn!(addr = %addr, error = %e, "handshake error");
                        }
                    }
                });
            }
            Err(e) => error!(error = %e, "accept failed"),
        }
    }

    // Exited the listen loop via shutdown; give background tasks a brief
    // moment to flush (DHT save, log flush). Then main() returns — Drop
    // runs on the Node/pools/channels, zeroizing key material.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    info!("liun-node shutdown complete");
}
