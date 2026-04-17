# liun-node: ITS-Secure Network Node

Production Rust implementation of the Liu protocol suite (Liup + Liun).

**255 Rust tests + 16 forge tests. Zero failures.**

## Why this exists

**Liun is information-theoretically secure** (ITS) — Shannon-style,
one-time-pad-class, unconditional. Not "computationally hard to
break"; *mathematically impossible* to break (in theory), even with
infinite computing power and unlimited time.

If computational cryptography ever fails — quantum computer, math
breakthrough, doesn't matter — every HTTPS connection, every encrypted
message, every signed transaction collapses overnight. Banking, medical
records, private messages, national secrets: the internet's privacy
layer becomes readable.

Liun doesn't rely on any of that (RSA, elliptic curves, AES, etc.).
Chat is just the first demo; the same ITS primitives secure any
traffic — web requests, financial settlements, IoT, anything that
needs privacy.

Anyone can run a node. Volunteers get paid from a public ETH pool
funded by sponsors — no user fees, no tokens, no stake. Fake nodes
earn nothing because payouts require trust derived from verified
protocol interactions, not capital or social connections.

It's the lifeboat for when comp crypto breaks.

See [docs/FUNDING.md](docs/FUNDING.md) for the funding design,
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what's protected and
what isn't, and [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire
formats.

## Quick Start

```bash
cargo test --workspace    # run all tests (190 pass)
cargo build --release     # build everything

# First-time setup: generate a config + identity interactively (or with --defaults).
# Echoes your new Node ID so you can share it with peers.
./target/release/liun-node --data-dir ~/.liun init            # interactive wizard
./target/release/liun-node --data-dir ~/.liun init --defaults # non-interactive

# Run the node — joins the network automatically via hardcoded genesis seed:
./target/release/liun-node --listen 0.0.0.0:7767 --dht-listen 0.0.0.0:7767

# Connect directly to a known peer address:
./target/release/liun-node --listen 0.0.0.0:7768 --peer 192.168.1.50:7767

# Run with DHT-based peer discovery (Kademlia, post-comp-crypto safe):
./target/release/liun-node --listen 0.0.0.0:7767 --dht-listen 0.0.0.0:7768 \
    --config config.toml   # config.toml lists [[dht_seeds]]

# Find a peer by node-ID via DHT and connect:
./target/release/liun-node --listen 0.0.0.0:7770 --dht-listen 0.0.0.0:7771 \
    --connect-to-id 4HeK8SZEQXBwm7rXvwbxyJKqqDn18TUvxfnuGNDg7dXK5x5cTZFMFAQaHKzhcVFudJ \
    --config config.toml

# ITS-secure chat — two people over the internet, no pre-shared key:
#   (1) Both peers first agree on a session-id (any short string, sent via any channel)
#   (2) Both peers load the same relays.toml (list of k bootstrap relays)
#   (3) Run a relay yourself (or use published ones) — see docs/RELAY.md

./target/release/chat listen  0.0.0.0:7770      --session-id mynight42 --relays ~/.config/liun/relays.toml  # host
./target/release/chat connect 203.0.113.1:7770  --session-id mynight42 --relays ~/.config/liun/relays.toml  # join

# Run a bootstrap relay (one of the k relays the chat uses):
./target/release/relay --listen 0.0.0.0:8080

# ITS-secure group chat (any number of people):
./target/release/groupchat --host 0.0.0.0:7770 --name Alice     # host
./target/release/groupchat --join 192.168.1.50:7770 --name Bob  # join
./target/release/groupchat --join 192.168.1.50:7770 --name Carol # join more
```

## Architecture

```
crates/
├── liuproto-core/    Core ITS primitives (112 tests incl. proptest + spec vectors + kani harnesses)
│   ├── gf61          GF(2^61-1) Mersenne prime field: add, sub, mul, inv, pow
│   ├── mac           Wegman-Carter polynomial MAC: scalar + 4-way parallel Horner (625M coef/s)
│   ├── noise         Box-Muller Gaussian from OS entropy (26.9M samples/sec)
│   ├── entropy       Background double-buffered entropy prefetch
│   ├── pool          OTP pool w/ key recycling + SharedPool (concurrent multi-producer refill)
│   ├── prewarm       Idle-time pool refill policy (top-K peers by recent traffic)
│   ├── privacy_amp   Toeplitz universal hash for Leftover Hash Lemma extraction
│   ├── storage       Persistent state: pools (v2 atomic + CRC), metadata, trust, identity, DHT
│   └── identity      384-bit auto-generated node identity (base58 canonical, hex compat)
│
├── liun-channel/     Liu channel management (14 tests)
│   ├── wire          Binary framing (8 bytes per exchange)
│   ├── channel       Single channel: connect, run_batch, close
│   ├── exchange      Full bidirectional signbit_nopa protocol over TCP
│   ├── handshake     Peer identification: LIUN magic + version + 384-bit ID + nonce
│   └── manager       Multi-channel lifecycle with parallel channel support
│
├── liun-dht/         Kademlia DHT for peer discovery (27 tests incl. parser fuzz)
│   ├── distance      384-bit XOR distance, k-bucket index
│   ├── routing       Kademlia routing table (384 buckets × K=20)
│   ├── message       Binary UDP wire protocol (PING/FIND/NODES, no signatures)
│   └── node          Async server + iterative parallel lookup (ALPHA=3)
│
├── liun-uss/         Threshold signatures (9 tests)
│   ├── lagrange      Interpolation: basis, evaluate, reconstruct
│   ├── shamir        Split (k-of-n) and reconstruct
│   ├── signer        Partial signing + combination via Lagrange
│   └── verifier      Deterministic polynomial consistency check
│
├── liun-dkg/         Distributed key generation (3 tests)
│   └── lib           Generate, distribute, verify, combine shares
│
├── liun-overlay/     Network overlay (17 tests, +4 integration)
│   ├── bootstrap     Multi-path PSK from k-of-k XOR over relays (no pre-shared key)
│   ├── relay_client  HTTP client for bootstrap dead-drops (POST/GET shares)
│   ├── relay_server  HTTP server for bootstrap dead-drops (used by liun-relay)
│   ├── directory     TOML parser for relays.toml
│   ├── peer_intro    XOR combination from introducer components
│   └── trust         Personalized PageRank with Sybil resistance
│
├── liun-consensus/   Trust-weighted BFT (9 tests)
│   ├── lib           Accept/reject with trust threshold
│   └── committee     Dynamic rolling committee: configurable size + rotation rate
│
├── liun-receipts/    Session-level ITS receipts, OFF the data path (15 tests + 3 e2e)
│   ├── ReceiptClaim, SignedClaim, ClaimBatch  (Wegman-Carter over GF(M61))
│   ├── SharedKey     cursor-based one-time-use byte stream from a Liu channel
│   └── OpRecorder    node-side session accumulator; batch-posts by each node itself
│
└── liun-tally/       Deterministic payout tally (16 tests) — a PURE FUNCTION
    ├── tally          (claims, trust, addr_book) → canonical payout list
    ├── tally_auto     same, but derives trust from verified interactions (no vouching)
    ├── AutoTrust      PageRank over interaction graph seeded from genesis nodes
    │                  Anti-gaming: DHT excluded, binary edges per peer, 52-epoch decay
    ├── merkle_root    OZ-compatible Merkle root + proofs (keccak at chain boundary)
    └── KeyStore       every node holds keys with its DIRECT peers only

contracts/
└── LiunPool.sol     Mainnet public-goods pool, ETH-denominated (16 forge tests)
    ├── deposit       anyone sends ETH (plain transfer also works)
    ├── postEpoch     ANY node publishes with anti-spam deposit (no committee)
    ├── invalidate    7-day challenge window; challenger submits conflicting root
    ├── finalize      after window, publisher's deposit refunded + small gas rebate
    └── claim         nodes withdraw ETH with Merkle proof
```

## End-to-End Tests

| Test | What it proves |
|---|---|
| `e2e_no_psk` | Two strangers with NO pre-shared key → ITS key agreement over TCP |
| `e2e_network` | 5-node full protocol: bootstrap → channels → DKG → sign → verify → consensus |
| `e2e_scale` | 50 nodes, 445 channels, committee selection, 5 epoch rotations, 10 signatures |
| `e2e_parallel` | Parallel channel throughput: 1→50 channels, measuring Mbps scaling |
| `e2e_two_processes` | Full lifecycle: bootstrap → exchange → persist → restart → reconnect |
| `e2e_ten_nodes` | 10-node full mesh: 45 pairwise exchanges, DKG, 20 signatures, consensus (13ms) |

## Chat Demo

Two binaries for demonstrating ITS-secure communication:

**`chat`** — Two-person encrypted chat. End-to-end ITS when any ITS RNG is available (`--rng auto` detects RDSEED, RNDR, or trandom). Lean-proved at every protocol link:

1. **PSK bootstrap** — k-of-k XOR secret sharing over k independent relays. No OOB key transfer. ITS if ≥1 relay unobserved. See [docs/RELAY.md](docs/RELAY.md).
2. **Per-message encryption** — One-Time Pad from a pool derived from the PSK.
3. **Per-message authentication** — Wegman-Carter polynomial MAC over GF(2⁶¹−1).
4. **Continuous key refresh** — background Liu protocol exchange (`signbit-nopa` variant: TRNG bits encrypted with OTP from the pool, MAC'd together with Liu-shaped mod-p wire values for tamper evidence). Toeplitz privacy amplification is applied to the exchange output. Multiplexed on the same TCP connection. Pool alternation across rounds gives +0.5 B/round net growth per pool — pool never exhausts. **Note**: the Liu noise-asymmetry mechanism is *not* what generates the key material in signbit-nopa — the TRNG does. The wire's Gaussian shape provides wrapped-uniformity for the MAC and the wire-leakage security proof. The full multi-exchange noise-asymmetry mechanism (Liup's `run_proto_multibit`) is implemented in `liuproto_core::link` as an in-process reference, but not wired into the network protocol (doing so would require either leaking `_last_real_sent` over the wire or switching to non-ITS mode).
5. **Reconnect handler** — survives TCP drops (WiFi glitches, ISP blips, proxy restarts) without re-bootstrapping. Pool state preserved in memory. Process death destroys key material (forward secrecy by design — pool is NOT persisted to disk).

Per-message display shows the full state: `Frame: 40B on wire (20B overhead) | MAC: ✓ (poly degree 20 over GF(2⁶¹-1), tag 8B) | OTP: 160 key bits withdrawn | Decrypt: 8µs | Pool: 10000B → 10000B (Liu-refilling)`.

**`relay`** — A stateless HTTP dead-drop for k-path bootstrap shares. Run one yourself to be one of the k relays your friends use. ~1 MB static binary, trivial to deploy.

**`groupchat`** — Multi-person encrypted chat. One host, any number of joiners. Each pairwise link independently ITS-secured. Host relays messages to all participants. Tested with 20 simultaneous users, 950 messages, sub-millisecond encryption latency.

## Operational features

- **Graceful shutdown**: SIGTERM triggers orderly shutdown — DHT peers saved, key material zeroized on drop, process exits cleanly. Second signal within `TimeoutStopSec` forces.
- **Health + metrics HTTP** via `--admin-listen <addr>` — `/health` returns JSON status, `/metrics` returns Prometheus format. Bind to loopback-only unless fronted by a reverse proxy.
- **DHT rate limiting**: per-source-IP token bucket (1000 queries / 10s window), drops over-limit silently.
- **Core-dump + ptrace hardening**: `prctl(PR_SET_DUMPABLE, 0)` at startup by default. `--mlock-memory` opt-in for `mlockall`. Systemd unit additionally enforces `MemorySwapMax=0`.
- **Constant-time crypto hot loop**: `Gf61` arithmetic branchless on secret data. MAC compare uses `subtle::ConstantTimeEq`.
- **Memory zeroization**: `Pool`, OTP buffers, MAC keys wiped on drop via `zeroize`.
- **Systemd unit + Dockerfile + distro packages + Grafana dashboard + Prometheus alerts** in `deploy/`, full deployment guide in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- **Supply chain**: `cargo audit` + `cargo deny` in CI, `deny.toml` policy file, reproducible-build verification, `docs/SECURITY.md` documents the discipline.
- **Threat model explicit**: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — adversary tiers A-G, what's protected, what's not, deployment checklist.
- **Wire protocol spec**: [docs/PROTOCOL.md](docs/PROTOCOL.md) — every byte of every wire format, version discipline, downgrade-attack analysis.
- **Node incentives**: [docs/FUNDING.md](docs/FUNDING.md) — one role (node), one binary, one wallet. Anyone runs a `liun-node` and gets paid for the work it does from a public-goods ETH pool. No stake, no fees, no committees, no pubkeys in the protocol layer. Payout tally is a deterministic pure function any node can re-run and challenge.

## Trust model

Trust is derived **automatically from verified protocol interactions**
— no human vouching, no manual registration, no social gating.

Every successful session (pipeline courier, relay share, Liu channel)
where both sides' MACs verify creates an edge in the interaction
graph. PageRank over this graph, seeded from the genesis node, gives
each node a trust score. Payouts = trust × volume.

### Anti-gaming measures

| Attack | Defence | Tested |
|---|---|---|
| **DHT query spam** — cheap UDP packets to farm trust edges | DHT queries (`OP_DHT_QUERY`) excluded from trust. Only sustained sessions (`OP_CHANNEL_BYTES`, `OP_RELAY_SHARE`) create edges. | `dht_queries_excluded_from_trust` |
| **Collusion inflation** — two nodes repeat sessions to inflate trust | Edges **deduplicated per unique peer pair**. 1000 sessions = 1 trust edge. | `repeated_sessions_give_one_trust_edge` |
| **Sybil cluster** — fake nodes interact only with each other | Zero edges to honest network → zero PageRank from seed → zero payouts. | `sybil_cluster_earns_nothing_auto_trust` |
| **Sybil client corroboration** — trusted server manufactures fake client | Both sides must have positive trust for a session to count toward payouts. | `sybil_client_cannot_inflate_trusted_server` |
| **Trust stagnation** — node earned trust long ago, stopped serving | **52-epoch decay window**. Old interactions contribute less; nodes that stop serving lose trust over time. | Structural (weight = window − age) |
| **Long-range pivot** — node earns trust honestly, then turns evil | Turning evil = bad MACs → sessions fail → no new trust edges form → trust decays. Detected automatically by protocol, not by humans. | Protocol-level (MAC verification) |

### What the genesis seed can and cannot do

The seed is the PageRank teleport root. It **cannot**:
- Grant trust without real MAC-verified interactions
- Forge interactions (would need the peer's SharedKey)
- Override the decay window

It **can**:
- Be the first node a new joiner interacts with (DHT bootstrap)
- Accumulate trust edges from real interactions with honest peers

Multiple seeds are supported (`GENESIS_SEEDS` array) for independence.

## RNG discipline

The ITS claim holds iff the random source is genuinely unpredictable.
Linux `/dev/urandom` is a CSPRNG (ChaCha20) — computationally
unpredictable but *not* information-theoretically random. A Liun node
in `urandom` mode delivers CSPRNG-strength output, honestly labelled.

Four backends, auto-detected via `--rng auto`:

| Mode | Source | Security | Auto-detect order |
|---|---|---|---|
| `rdseed` | Intel RDSEED instruction | ITS (hardware TRNG) | 1st |
| `rndr` | ARM RNDR instruction (M1+, Graviton 3+) | ITS (hardware TRNG) | 2nd |
| `trandom` | [trandom](https://github.com/noospheer/trandom) daemon (`/dev/trandom`) | ITS (multi-source + LHL extraction) | 3rd |
| `urandom` | `/dev/urandom` via `getrandom` | Computational (CSPRNG) | fallback |

Each ITS backend refuses to start if unavailable — **no silent fallback**.
`--rng auto` picks the best available and tells you what it chose.

**Cloud VMs** typically mask RDSEED. Install trandom for ITS on any
x86 VM: `sudo ./scripts/install-trandom.sh`. After that, `--rng auto`
detects `/dev/trandom` automatically.

Both `chat` and `liun-node` accept `--rng <mode>`. The banner reflects
the chosen mode honestly.

## Peer Discovery (Node Network)

`liun-node` daemons can join a self-organizing peer network via the bundled Kademlia DHT. **No signatures anywhere in the discovery layer** — entries are unauthenticated hints, validated when the channel layer dials them and runs the Liun ITS handshake. This makes the discovery layer trivially survivable past a computational-crypto break: poisoning becomes a discoverability nuisance, never a confidentiality or impersonation attack. See [docs/DHT.md](docs/DHT.md).

```bash
# First node — no seeds, becomes the genesis seed
./target/release/liun-node --listen 0.0.0.0:7771 --dht-listen 0.0.0.0:7771

# New node joining — needs only ONE existing peer's id+addr in config.toml:
#   [[dht_seeds]]
#   id   = "4HeK8SZEQXBwm7rXvwbxyJKqqDn18TUvxfnuGNDg7dXK5x5cTZFMFAQaHKzhcVFudJ"
#   addr = "203.0.113.10:7771"
./target/release/liun-node --listen 0.0.0.0:7772 --dht-listen 0.0.0.0:7772 --config config.toml

# Find any peer by ID (transitive discovery via DHT):
./target/release/liun-node --listen 0.0.0.0:7773 --dht-listen 0.0.0.0:7773 \
    --config config.toml --connect-to-id <peer-base58-id>
```

After first run, the node persists its known peers to `~/.liun/dht_peers.bin` and restores them on next startup — seeds become optional after the first session. Periodic refresh (every 5 min) keeps the routing table fresh.

**Scale:** O(log N) lookups, O(K·log N) routing-table size. ~30 hops at 1B nodes; ~100µs lookup latency on local mesh of 20 nodes.

**Node IDs:** 384-bit, displayed as base58 (Bitcoin alphabet — ~65 chars, no `0/O/I/l` confusion, URL- and shell-safe). The 96-char hex form is also accepted everywhere for backward compat. Example ID: `4HeK8SZEQXBwm7rXvwbxyJKqqDn18TUvxfnuGNDg7dXK5x5cTZFMFAQaHKzhcVFudJ`.

On connect, users see:
```
╔══════════════════════════════════════════════════╗
║  ITS-SECURE CHAT                                 ║
╠══════════════════════════════════════════════════╣
║  Encryption: One-Time Pad (perfect secrecy)      ║
║  Authentication: Wegman-Carter MAC (unforgeable)  ║
║  Security: INFORMATION-THEORETIC                 ║
║  Quantum resistant: YES (no computation helps)   ║
║  Proof: verified in Lean 4 (0 sorry)             ║
╚══════════════════════════════════════════════════╝
```

## Performance

| Metric | Value |
|---|---|
| MAC evaluation (113k coefficients) | 180 µs (625 M coefficients/sec) — 4-way parallel Horner |
| Gaussian noise generation | 26.9 M samples/sec |
| Pipeline courier (single channel) | ~5 Gbps (MAC-bound; ~10 Gbps with AVX-512) |
| Pipeline courier (EC2 ↔ home, tested) | ~100 Mbps (link-bound, not protocol-bound) |
| Wire overhead | 0.8% (8-byte MAC per 1 KB chunk) |

### Pipeline courier mode

The original signbit_nopa exchange sends Gaussian noise round-trips
(~0.8% extraction ratio, RTT-bound). Pipeline courier mode replaces
this with continuous bidirectional streaming of OTP-encrypted random
bytes — no round-trip wait, ~99.2% extraction ratio. A single TCP
connection saturates the link or the MAC engine, whichever is smaller.

The Gaussian noise machinery was designed for the full Liup multi-bit
protocol (noise-correlation key agreement). In signbit_nopa — which is
what's deployed — the sign bits are already OTP-encrypted and sent
directly. The courier just removes the unnecessary noise overhead.

**Security:** fully proved in Lean 4 (`LiupProofs/Liun/PipelineCourier.lean`,
zero `sorry`). The proof includes:
- **Self-rekeying chain induction** (`chain_all_keys_uniform`):
  Eve's bias on the key at every chunk index i = 0, 1, ..., T is
  exactly 0, for any T. Proved by `Nat.rec`: base case (PSK-derived
  key is uniform) + inductive step (OTP with uniform key → uniform
  ciphertext → next key hidden).
- **Total information theorem** (`eve_total_information_zero`):
  sum of Eve's biases across all T chunks = 0.
- Per-chunk forgery < 10⁻¹⁴. 1 GB transported < 10⁻⁸.
- One axiom: TRNG outputs are uniform (physics, not math).

### Why multiple channels are no longer needed for throughput

Pipeline courier eliminates the round-trip bottleneck that originally
motivated parallel channels. One pipelined TCP connection achieves
~5 Gbps (MAC-bound with current 4-way Horner; ~10 Gbps projected with
AVX-512). Multiple channels per peer are still useful for redundancy
and reconnect resilience, but not for raw throughput.

## Security Proofs

All cryptographic properties are machine-verified in Lean 4 — see [LiupProofs/](../LiupProofs/).
31 files, zero `sorry`, zero errors. The Rust implementation matches the proved algorithms:

- `gf61` arithmetic matches `SchwartzZippel.lean` (polynomial root bound)
- `mac` Horner evaluation matches `WegmanCarter.lean` (forgery ≤ d/|F|)
- `noise` Box-Muller matches `Theorem1.lean` (TV bound on sign bits)
- `pool` recycling matches `XORBias.lean` (constant per-bit security)
- `shamir` / `lagrange` match `ShamirPrivacy.lean` (Vandermonde invertibility)
- `trust` PageRank matches `SybilResistance.lean` (attack trust bounded)
- `committee` + `consensus` match `Composition.lean` (union bound)
- `pipeline courier` matches `PipelineCourier.lean` (self-rekeying chain induction: Eve's bias on every key = 0 for any number of chunks T, proved by `Nat.rec`; per-chunk forgery < 10⁻¹⁴; 1 GB total < 10⁻⁸)

## Configuration

Create `config.toml`:

```toml
sigma_over_p = 2.0        # σ/p ratio (2 = default, δ_TV ≈ 10⁻³⁴)
batch_size = 100000        # sign bits per batch
n_nodes = 100              # expected network size
bootstrap_peers = [        # initial peers for joining
    "node1.example.com:7767",
    "node2.example.com:7767",
]
```

See [LiupProofs/PARAMETER_GUIDE.md](../LiupProofs/PARAMETER_GUIDE.md) for security-level
parameter selection with machine-verified bounds.
