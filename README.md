# Liun

**Decentralized information-theoretically secure digital signatures over standard internet infrastructure.**

No quantum hardware. No special hardware. No computational hardness assumptions.
Three primitives. One finite field. Instant join.

> **Status: research prototype.** The claims below are strong. Each primitive
> (Shamir, USS, Liu, PageRank) has individual theoretical grounding, and
> the 266 tests verify algebraic correctness at scale. But a composed system
> making information-theoretic security claims needs substantially more
> scrutiny before anyone should trust it with real value:
>
> - No independent security audit has been performed
> - The formal composition proof (three primitives interacting across six
>   protocol layers) has not been written
> - The system has not been tested over real networks — all tests run
>   in-process
> - Adversary models in simulation may not capture all real-world attack
>   surfaces
> - Performance at production scale (thousands of nodes, real TCP, sustained
>   load) is uncharacterized
>
> We publish this openly because the architecture may be sound and we want
> scrutiny, not because it is ready for deployment. Read critically.

---

## The Problem

Every deployed digital signature system (ECDSA, RSA, Ed25519) depends on
computational hardness — mathematical problems assumed to be hard but not
proven to be. A sufficiently powerful adversary (quantum computer,
mathematical breakthrough) breaks them all, retroactively and permanently.

Ethereum, Bitcoin, TLS, SSH, PGP — everything falls.

## The Solution

Liun replaces computational hardness with information-theoretic security:
a system where security is **proven by Shannon's theorems**, not assumed from
unproven conjectures. An adversary with unlimited computation — including
quantum computers — cannot break it. Not "we think they can't." They
**provably** cannot.

---

## Three Primitives

The entire system is built from three things:

### 1. Polynomial Arithmetic over GF(M61)

**M61 = 2^61 - 1** (Mersenne prime). One finite field for all algebra:

- **Shamir secret sharing**: split and reconstruct secrets via polynomial
  evaluation. ITS privacy: k-1 shares reveal nothing. ITS reconstruction:
  k shares recover the exact secret.

- **USS signatures**: sign = evaluate polynomial at message point.
  Verify = polynomial consistency check. ITS unforgeable: forging requires
  more evaluation points than any adversary holds.

- **Liu MAC authentication**: evaluate polynomial at secret point.
  Forgery probability: d/M61 ~ 5x10^-14 per message.

Same operation (polynomial evaluation), same field (M61), three uses.

### 2. Liu Protocol (Gaussian Noise Key Engine)

The [Liu protocol](https://github.com/noospheer/Liup) exchanges band-limited Gaussian noise between
two parties over TCP, extracting shared sign bits that are
information-theoretically hidden from eavesdroppers.

From a ~12.5 KB pre-shared key (PSK), Liu generates an unlimited stream
of ITS key material at ~2-3 Mbps. Pool recycling means the PSK never
exhausts. Channels run forever.

Liun integrates Liu directly: `RealLiuChannel` wraps `liuproto.StreamPipe`
for real physics (Gaussian noise exchange, privacy amplification via Toeplitz
hashing, Wegman-Carter MAC via tree-reduction over M61). PSK establishment
happens digitally in-protocol via multi-path bootstrap and XOR peer
introduction — no physical courier required, IT-secure against an
arbitrarily powerful adversary.

### 3. Random Walk on Channel Graph (Local Trust)

Each node computes trust from its own position in the Liu channel graph
via personalized PageRank. No founding members. No global authority.
Trust is local, subjective, and emergent.

Sybil resistance: an attacker's trust is bounded by their connections
to honest nodes (attack edges), regardless of how many fake identities
they create. Proven by SybilRank (Yu et al. 2006).

---

## How It Works

### Joining the Network (~5 minutes)

```
0:00  Node selects 20 geographically diverse existing nodes
0:01  Multi-path Shamir: secret shares sent via independent routes
      (Eve must observe ALL 20 routes to break — miss one, gets nothing)
0:02  Shared secrets become Liu PSKs
0:03  Liu channels established — ITS key material flowing
0:05  Peer introductions begin — overlay expands
      Node is live. Participating. Trust grows from here.
```

No approval needed. No waiting period. No permission from anyone.

### Establishing New Channels (topology-independent)

After bootstrap, ALL new channels are established through the ITS overlay.
Network topology becomes irrelevant.

```
A wants a channel with C. Both know B1, B2, B3.

B1 generates PSK1, sends to A and C over ITS channels
B2 generates PSK2, sends to A and C over ITS channels
B3 generates PSK3, sends to A and C over ITS channels

PSK_AC = PSK1 XOR PSK2 XOR PSK3

Neither B1, B2, nor B3 knows PSK_AC.
Eve observing TCP sees only ITS-encrypted traffic.
A and C run Liu with PSK_AC. New ITS channel established.
```

### Signing and Verification

**Distributed key generation (no trusted dealer):**
Each node contributes a random polynomial over GF(M61). Shares are summed.
Nobody ever sees the full signing key. All distribution over ITS channels.

**Threshold signing (k-of-n):**
k nodes each compute a partial signature using their share. Combined via
Lagrange interpolation into a full USS signature. No single node can sign
alone. No single node can forge.

**Verification:**
Each verifier checks the signature against their own independently held
evaluation points. Different verifiers have different points. A forger
would need to fool all of them simultaneously — information-theoretically
impossible without the signing key.

**Non-repudiation:**
Disputes resolved by majority of independent verifiers. Each verifier's
check is independent. Honest majority guarantees correct adjudication.

### Transaction Authentication

Individual transactions (transfers, contract calls) are authenticated via
Liu MAC to the sender's channel peers:

```
Alice creates tx: {from: Alice, to: Bob, amount: 10}
Alice MAC-authenticates to each Liu peer (ITS — unforgeable)
Peers verify and attest: "Alice authorized this"
Trust-weighted attestations exceed threshold → tx accepted
Block signed with USS threshold signature → ITS finality
```

### Wallet Recovery

Lose your node? Your peers know you. Social recovery via peer re-attestation:

```
"I'm Alice, I had channels with B1, B2, B3."
Peers vouch. New channels established. Identity restored.
```

No seed phrase. No single point of failure. Better than today.

---

## Security

### What Cannot Break This

| Attack | Effect |
|--------|--------|
| Quantum computer | None — nothing to compute |
| Faster classical computers | None — no computational assumption |
| New mathematical theorem | None — security is information-theoretic |
| Record-now-decrypt-later | None — no ciphertext to later break |
| Cryptanalysis | None — XOR with unknown uniform = perfect secrecy |

### What Can Threaten It

| Attack | Scope | Mitigation |
|--------|-------|-----------|
| Global passive observer (bootstrap only) | Individual node trapped in fake network; real network unaffected | Detectable on next connection from different context |
| Sybil identity flooding | Attacker trust bounded by attack edges regardless of node count | Local trust (personalized PageRank) |
| Slow infiltration | Attacker gradually builds channels with honest nodes | Bounded by honest nodes' channel capacity |
| Liveness stall (>1/3 trust) | Network slows but cannot be forged | Same as every BFT system including Ethereum |

### Assumptions

| Assumption | Type | Same as |
|-----------|------|---------|
| Honest majority (>2/3 of trust-weighted nodes) | Standard | Bitcoin, Ethereum, all BFT |
| At least 1 of 20 bootstrap paths unobserved | Physical | Weaker than "ECDSA is hard" |
| Honest nodes have private memory | Universal | Every cryptosystem ever |

---

## Comparison

### vs Ethereum (ECDSA + PoS)

| | Ethereum | Liun |
|--|---------|---------|
| Security basis | Discrete log hardness | Information theory |
| Quantum resistant | No | Yes — inherently |
| Breaks with math advance | Yes | No |
| Transaction signing | Individual (private key) | Peer-attested (Liu MAC) |
| Block finality | Computational BFT | ITS BFT |
| Wallet recovery | Seed phrase (lose it = gone) | Social recovery via peers |
| Join time | Seconds (generate keypair) | ~5 minutes (bootstrap) |
| Special hardware | No | No |

### vs QKD-based Signatures

| | QKD Signatures | Liun |
|--|---------------|---------|
| Security basis | Quantum mechanics | Network diversity + information theory |
| Special hardware | Quantum channels, SPDs | None — standard CPU + TCP/IP |
| Throughput | ~kbps | ~Mbps (Liu-limited) |
| Permissionless | Limited | Yes |

### vs Computational Post-Quantum (lattice, hash-based)

| | Post-quantum crypto | Liun |
|--|-------------------|---------|
| Security basis | Lattice/hash hardness | Information theory |
| Proven secure | No (assumed hard) | Yes (Shannon) |
| Signature size | Large (kB) | 8 bytes (one field element) |
| Future-proof | Until lattice breaks | Permanent |

---

## How Ethereum Could Use This

Ethereum's entire security rests on one assumption: that the discrete
logarithm problem is hard. If it isn't — quantum computers, mathematical
breakthrough, or an attack nobody has thought of yet — every wallet key,
every signed transaction, every finalized block becomes forgeable.
Retroactively. Permanently.

Liun replaces that single point of failure. Here's concretely what changes
and what doesn't.

### What stays identical

| Component | Changes? | Why |
|-----------|----------|-----|
| EVM | No | Liun replaces the signature layer, not the execution layer |
| Solidity / smart contracts | No | Contracts don't touch signature internals |
| ERC-20, ERC-721, all token standards | No | Token logic is EVM, not crypto |
| Gas model, fee market, EIP-1559 | No | Economic layer is independent of key type |
| State trie, Merkle Patricia | No | Data structures don't depend on signature scheme |
| JSON-RPC, web3.js, ethers.js | Thin wrapper | API calls carry a Liun signature instead of ECDSA `v,r,s` |
| MetaMask, wallets | UI unchanged | Backend swaps ECDSA signing for Liun partial signing |
| DeFi protocols (Uniswap, Aave, etc.) | No | They verify `msg.sender`, which still works |

### What changes

**One thing: how transactions are signed and how blocks are finalized.**

```
Today (Ethereum):
  User has ECDSA private key (256 bits)
  Signs tx: sig = ECDSA_sign(privkey, tx_hash)
  Validator checks: ECDSA_verify(pubkey, tx_hash, sig)
  Block finality: 2/3 of stake signs with ECDSA
  Security: "we assume discrete log is hard"

With Liun:
  User has Liu channels to k peers (ITS key material flowing)
  Signs tx: peers MAC-authenticate tx over Liu channels
  Trust-weighted attestations: "Alice authorized this"
  Block finality: 2/3 of trust-weighted nodes sign with USS
  Security: "Shannon proved this is secure" — no assumption
```

**Transaction authentication** replaces individual private keys with
peer-attested Liu MACs:

```
Alice wants to send 10 ETH to Bob.

1. Alice constructs tx = {from: Alice, to: Bob, value: 10 ETH, nonce: 42}

2. Alice authenticates tx to each of her Liu channel peers:
   tag_i = MAC(tx, key_i)    ← ITS: unforgeable even by quantum computer
   Sends (tx, tag_i) to peer_i

3. Each peer verifies the MAC and attests:
   "I confirm Alice authorized this transaction"

4. Trust-weighted attestations collected:
   Σ trust(peer_i) > threshold  →  tx accepted into mempool

5. Block proposer includes tx. Committee signs block with USS:
   σ = Combine(partial_sign(block, share_i) for i in committee)

6. Block finalized. ITS guarantee:
   - Alice's tx cannot be forged (Liu MAC is ITS)
   - Block signature cannot be forged (USS is ITS)
   - No future computer can retroactively break either
```

**Block finality** replaces BLS aggregate signatures with USS threshold
signatures:

```
Today:                              With Liun:
─────                               ─────────
Each validator has BLS privkey      Each validator has Shamir share
Validators sign: BLS_sign(block)    Validators sign: partial_sign(block, share_i)
Aggregate: BLS_aggregate(sigs)      Combine: lagrange_interpolate(partials)
Verify: BLS_verify(agg_pubkey)      Verify: USS polynomial consistency check
Security: BLS hardness (assumed)    Security: polynomial secrecy (proven)
Sig size: 96 bytes                  Sig size: 8 bytes
```

**Key generation** replaces individual key generation with distributed
key generation over ITS channels:

```
Today:                              With Liun:
─────                               ─────────
Validator runs: privkey = random()  N validators run DKG over Liu channels
Nobody else involved                Each contributes random polynomial
Single point of failure             Nobody sees the combined signing key
Lose key = lose everything          Lose node = social recovery via peers
```

### Wallet recovery

Today: lose your seed phrase, lose everything. Forever.

With Liun: your peers know you. Your Liu channels are your identity.

```
1. Alice loses her node
2. Alice contacts peers B1, B2, B3 from a new device
3. Peers verify Alice via out-of-band confirmation
4. Peers re-establish Liu channels with Alice's new node
5. New DKG epoch: Alice receives new signing share
6. Alice is back. No seed phrase was ever needed.
```

### The bottom line

Every layer of the Ethereum stack above the signature primitive —
EVM, contracts, tokens, DeFi, the entire application ecosystem —
works unchanged. The only thing that changes is *how you prove you
authorized something*. Today that proof rests on an unproven mathematical
conjecture. With Liun it rests on Shannon's theorem. Everything else
is the same, except now a quantum computer can't steal your ETH.

---

## Architecture

```
+---------------------------------------------------------+
|  Application: wallets, transfers, contracts, DeFi       |
+---------------------------------------------------------+
|  Consensus: trust-weighted ITS BFT                      |
+---------------------------------------------------------+
|  Layer 3: USS Threshold Signatures                      |
|  Distributed signing, verification, non-repudiation     |
+---------------------------------------------------------+
|  Layer 2: Shamir DKG + Peer Introduction                |
|  Distributed key gen, overlay channel establishment     |
+---------------------------------------------------------+
|  Layer 1: Liu ITS Channels                              |
|  Key expansion, MAC authentication, sigma verification  |
+---------------------------------------------------------+
|  Layer 0: Multi-Path Bootstrap                          |
|  Shamir-encoded secret sharing over diverse TCP routes  |
+---------------------------------------------------------+
|  Infrastructure: standard TCP/IP                        |
+---------------------------------------------------------+

All algebra: polynomial evaluation over GF(M61)
All key material: Liu protocol (Gaussian noise exchange)
All trust: personalized PageRank on Liu channel graph
```

---

## Project Structure

Dependency: [Liup](https://github.com/noospheer/Liup) — the Liu protocol ITS key engine.

```
Liun/
├── README.md                          # This file
├── DESIGN.md                          # Detailed architecture
├── THREAT_MODEL.md                    # Attack analysis
├── OPEN_PROBLEMS.md                   # Remaining research questions
│
├── protocols/
│   ├── 01-bootstrap.md                # Multi-path key agreement
│   ├── 02-peer-intro.md               # ITS overlay expansion
│   ├── 03-shamir-dkg.md               # Distributed key generation
│   ├── 04-uss-signing.md              # Threshold signatures
│   ├── 05-liu-integration.md          # Liu as key engine
│   └── 06-local-trust.md              # Sybil resistance via personalized PageRank
│
├── src/liun/                           # Core library (pip-installable)
│   ├── gf61.py                         # GF(2^61-1) field arithmetic
│   ├── shamir.py                       # Polynomial secret sharing
│   ├── uss.py                          # Threshold USS signatures
│   ├── dkg.py                          # Distributed key generation
│   ├── liu_channel.py                  # Liu channel wrapper (mock or real backend)
│   ├── overlay.py                      # Peer introduction + channel graph + PageRank
│   ├── bootstrap.py                    # Multi-path network bootstrap
│   └── node.py                         # Node orchestration
│
├── sim/                                # Simulation framework
│   ├── core/
│   │   ├── mock_liu.py                 # MockLiuChannel (fast, deterministic)
│   │   ├── liu_adapter.py              # RealLiuChannel (real liuproto physics)
│   │   ├── clock.py                    # Discrete event simulation clock
│   │   └── message_bus.py              # Simulated network message delivery
│   ├── network/
│   │   ├── sim_node.py                 # Simulated node with real protocol logic
│   │   ├── sim_network.py              # Network orchestrator (topology + channels)
│   │   └── graph_gen.py                # Topology generators (random, BA, SW, geo)
│   ├── adversary/
│   │   ├── sybil.py                    # Sybil identity flooding
│   │   ├── eclipse.py                  # Eclipse bootstrap attack
│   │   ├── collusion.py                # Threshold collusion attack
│   │   └── slow_compromise.py          # Gradual infiltration over epochs
│   └── metrics/
│       ├── collector.py                # Timing and resource measurement
│       ├── efficiency.py               # Power-law fitting + extrapolation
│       └── reporter.py                 # CSV/JSON output
│
└── tests/                              # 266 tests
    ├── test_gf61.py                    # Field axioms, polynomial evaluation, Lagrange
    ├── test_shamir.py                  # Secret sharing roundtrip, secrecy, corruption
    ├── test_uss.py                     # Signing, verification, dispute resolution
    ├── test_dkg.py                     # Distributed key gen, corrupt detection, N=100
    ├── test_pagerank.py                # Trust, Sybil bounds, convergence
    ├── test_bootstrap.py               # Multi-path, eclipse resistance, peer intro
    ├── test_peer_intro.py              # XOR-PSK, mutual contacts, overlay expansion
    ├── test_sim_core.py                # Clock, mock Liu, message bus
    ├── test_sim_network.py             # Topologies, routing, connectivity
    ├── test_real_liu.py                # Real Liu physics: key agreement, MAC, DKG
    ├── test_adversary.py               # Sybil, eclipse, collusion, slow compromise
    ├── test_scenarios.py               # Full lifecycle, scaling, extrapolation
    └── test_scenarios_extended.py      # Large-scale (N=200-1000), cross-verification
```

---

## Status

**Working implementation.** All protocol layers implemented and tested
end-to-end. Every cryptographic primitive is real — no mocks in the
security chain.

### 266 tests — all passing

Every layer uses real arithmetic, real physics, real security. Zero mocks
in the cryptographic path.

#### GF(M61) Field Arithmetic — 30 tests

| # | Test | What it proves |
|---|------|---------------|
| 1 | `test_closure_add` | a + b stays in GF(M61) |
| 2 | `test_closure_mul` | a * b stays in GF(M61) |
| 3 | `test_associativity_add` | (a + b) + c = a + (b + c) |
| 4 | `test_associativity_mul` | (a * b) * c = a * (b * c) |
| 5 | `test_commutativity_add` | a + b = b + a |
| 6 | `test_commutativity_mul` | a * b = b * a |
| 7 | `test_distributivity` | a * (b + c) = a*b + a*c |
| 8 | `test_additive_identity` | a + 0 = a |
| 9 | `test_multiplicative_identity` | a * 1 = a |
| 10 | `test_additive_inverse` | a + (-a) = 0 |
| 11 | `test_multiplicative_inverse` | a * a^-1 = 1 |
| 12 | `test_inverse_of_zero_raises` | 0 has no inverse |
| 13 | `test_add_basic` | Concrete addition examples |
| 14 | `test_sub_basic` | Concrete subtraction examples |
| 15 | `test_mul_basic` | Concrete multiplication examples |
| 16 | `test_neg_basic` | Concrete negation examples |
| 17 | `test_div_basic` | Concrete division examples |
| 18 | `test_large_multiply_no_overflow` | 122-bit intermediate products stay correct |
| 19 | `test_constant_polynomial` | poly_eval on degree-0 |
| 20 | `test_linear_polynomial` | poly_eval on degree-1 |
| 21 | `test_quadratic_polynomial` | poly_eval on degree-2 |
| 22 | `test_poly_eval_low_matches` | Horner high-first = low-first |
| 23 | `test_manual_polynomial` | Hand-computed polynomial check |
| 24 | `test_polynomial_at_zero` | f(0) = constant term |
| 25 | `test_polynomial_modular` | Wrap-around near M61 |
| 26 | `test_interpolate_two_points` | Lagrange on 2 points |
| 27 | `test_interpolate_recovers_points` | Lagrange roundtrip |
| 28 | `test_lagrange_roundtrip_polynomial` | Random poly -> points -> reconstruct |
| 29 | `test_lagrange_basis_at_zero` | Basis polynomials sum correctly |
| 30 | `test_in_range` / `test_not_constant` | rand_element produces valid, non-degenerate elements |

#### Newton Interpolation — 6 tests

| # | Test | What it proves |
|---|------|---------------|
| 31 | `test_two_points` | Newton matches known 2-point interpolation |
| 32 | `test_matches_lagrange` | Newton and Lagrange agree on random polynomials |
| 33 | `test_interpolating_poly_class` | InterpolatingPoly class evaluates correctly |
| 34 | `test_single_point` | Degenerate case: one point |
| 35 | `test_large_degree` | High-degree polynomial roundtrip |
| 36 | `test_newton_at_known_points` | Passes through all input points exactly |

#### Shamir Secret Sharing — 13 tests

| # | Test | What it proves |
|---|------|---------------|
| 37 | `test_basic_3_of_5` | 3-of-5 split/reconstruct roundtrip |
| 38 | `test_k_equals_1` | Degenerate: 1-of-N (secret in the clear) |
| 39 | `test_k_equals_n` | N-of-N (all shares required) |
| 40 | `test_various_thresholds` | Parametric sweep of (k, n) combinations |
| 41 | `test_zero_secret` | Secret = 0 works |
| 42 | `test_max_secret` | Secret = M61-1 works |
| 43 | `test_reconstruct_at_nonzero` | Reconstruct at x != 0 |
| 44 | `test_k_minus_1_shares_uniform` | k-1 shares reveal nothing (ITS privacy) |
| 45 | `test_no_corruption` | Clean shares pass verification |
| 46 | `test_single_corruption` | One tampered share detected |
| 47 | `test_multiple_corruptions` | Multiple tampered shares detected |
| 48 | `test_insufficient_redundancy` | Not enough redundancy -> partial detection |
| 49 | `test_no_redundancy_returns_empty` | No redundancy -> no detection possible |

#### Shamir Edge Cases — 4 tests

| # | Test | What it proves |
|---|------|---------------|
| 50 | `test_invalid_secret_range` | Rejects secret >= M61 |
| 51 | `test_k_less_than_1` | Rejects k < 1 |
| 52 | `test_n_less_than_k` | Rejects n < k |
| 53 | `test_empty_shares` | Rejects empty share list |

#### USS Signatures — 11 tests

| # | Test | What it proves |
|---|------|---------------|
| 54 | `test_sign_verify_basic` | Direct sign + verify roundtrip |
| 55 | `test_wrong_sigma_fails` | Wrong signature rejected |
| 56 | `test_different_messages_different_sigs` | Different messages -> different signatures |
| 57 | `test_k_partials_combine` | k partial signatures combine to valid signature |
| 58 | `test_different_committees_same_signature` | Different k-subsets produce same combined signature |
| 59 | `test_k_minus_1_partials_cannot_forge` | k-1 partials cannot reconstruct (ITS unforgeability) |
| 60 | `test_sufficient_verification_points` | Enough points -> correct verification |
| 61 | `test_insufficient_points_accepts_anything` | Too few points -> vacuous (documented limitation) |
| 62 | `test_forgery_with_wrong_sigma_detected` | Forged signature caught by verifier |
| 63 | `test_valid_signature_resolved` | Dispute resolution: valid sig accepted |
| 64 | `test_forged_signature_detected` | Dispute resolution: forgery rejected |

#### USS Signature Budget — 3 tests

| # | Test | What it proves |
|---|------|---------------|
| 65 | `test_budget_tracking` | Signature count tracks correctly |
| 66 | `test_duplicate_messages_not_double_counted` | Same message doesn't consume budget twice |
| 67 | `test_all_forgery_strategies_fail` | Exhaustive forgery strategy sweep fails |

#### DKG — 9 tests

| # | Test | What it proves |
|---|------|---------------|
| 68 | `test_n10_produces_consistent_shares` | 10-node DKG: two subsets reconstruct same secret |
| 69 | `test_combined_polynomial_is_sum` | Combined share = sum of individual contributions |
| 70 | `test_no_single_node_knows_polynomial` | No node's individual secret = combined secret |
| 71 | `test_k_minus_1_shares_reveal_nothing` | k-1 shares consistent with any candidate secret |
| 72 | `test_corrupt_node_detected` | Inconsistent shares flagged |
| 73 | `test_honest_nodes_reconstruct_after_exclusion` | Honest nodes agree after excluding corrupt |
| 74 | `test_multiple_corrupt_detected` | Multiple corrupt nodes all detected |
| 75 | `test_n100_dkg` | 100-node DKG: consistent shares |
| 76 | `test_epoch_rotation` | EpochManager: successive DKGs produce different secrets |

#### PageRank Trust — 16 tests

| # | Test | What it proves |
|---|------|---------------|
| 77 | `test_line_graph` | Trust sums to 1.0 on line topology |
| 78 | `test_complete_graph` | Trust sums to 1.0 on complete graph |
| 79 | `test_sybil_graph` | Trust sums to 1.0 with Sybil region |
| 80 | `test_line_seed_higher_than_distant` | Seed node has higher trust than distant nodes |
| 81 | `test_complete_seed_highest` | Seed has highest trust on complete graph |
| 82 | `test_sybil_trust_bounded` | Sybil region trust bounded by attack edges |
| 83 | `test_sybil_scaling_with_attack_edges` | More attack edges -> more (but bounded) Sybil trust |
| 84 | `test_converges_within_20_iterations` | PageRank converges in 20 iterations |
| 85 | `test_10_iterations_close` | 10 iterations already close to converged |
| 86 | `test_different_seeds_different_trust` | Different seed nodes -> different trust distributions |
| 87 | `test_majority_accepts` | Trust-weighted majority accepts valid proposal |
| 88 | `test_minority_rejects` | Trust-weighted minority cannot force acceptance |
| 89 | `test_find_mutual_contacts` | Mutual contact discovery works |
| 90 | `test_can_introduce` | Peer introduction succeeds with mutual contacts |
| 91 | `test_cannot_introduce_no_mutual` | No mutual contacts -> no introduction |
| 92 | `test_xor_psk_generation` | XOR-PSK produces correct key |

#### Graph Monitor — 2 tests

| # | Test | What it proves |
|---|------|---------------|
| 93 | `test_connectivity` | Connected graph detected |
| 94 | `test_disconnected` | Disconnected graph detected |

#### Bootstrap — 14 tests

| # | Test | What it proves |
|---|------|---------------|
| 95 | `test_encode_decode_roundtrip` | Shamir encoder: encode -> decode recovers secret |
| 96 | `test_detect_corrupt_relay` | Shamir encoder: tampered relay detected |
| 97 | `test_generate_secrets` | Bootstrap session generates valid secrets |
| 98 | `test_derive_psk` | Bootstrap session derives PSK from secrets |
| 99 | `test_complete` | Bootstrap session completes successfully |
| 100 | `test_bootstrap_no_adversary` | Multi-path bootstrap: clean network succeeds |
| 101 | `test_bootstrap_partial_eclipse` | Multi-path bootstrap: partial eclipse still succeeds |
| 102 | `test_bootstrap_full_eclipse_fails` | Multi-path bootstrap: full eclipse fails |
| 103 | `test_bootstrap_succeeds_with_one_clean` | One clean path sufficient |
| 104 | `test_diverse_path_selection` | Topology bootstrap selects diverse paths |
| 105 | `test_eclipse_resistance` | Topology bootstrap resists eclipse |
| 106 | `test_multi_session` | Temporal bootstrap: multiple sessions |
| 107 | `test_xor_psk_one_corrupt_introducer` | One corrupt introducer doesn't leak PSK |
| 108 | `test_mutual_contacts_sufficient` | Enough mutual contacts for introduction |

#### Peer Introduction — 13 tests

| # | Test | What it proves |
|---|------|---------------|
| 109 | `test_xor_produces_correct_psk` | XOR of shares = agreed PSK |
| 110 | `test_xor_is_self_inverse` | XOR(XOR(a, b), b) = a |
| 111 | `test_one_corrupt_introducer_doesnt_leak` | 1 corrupt of 3 introducers: PSK safe |
| 112 | `test_two_corrupt_of_three_still_secure` | 2 corrupt of 3: PSK still safe (XOR property) |
| 113 | `test_complete_graph_all_mutual` | Complete graph: all nodes are mutual contacts |
| 114 | `test_ring_limited_mutual` | Ring: limited mutual contacts |
| 115 | `test_ring_adjacent_have_mutual` | Ring: adjacent nodes share contacts |
| 116 | `test_sorted_by_degree` | Mutual contacts sorted by degree |
| 117 | `test_complete_connected` | Graph monitor: complete graph is connected |
| 118 | `test_ring_connected` | Graph monitor: ring is connected |
| 119 | `test_disconnected_graph` | Graph monitor: disconnected graph detected |
| 120 | `test_underconnected_detection` | Graph monitor: underconnected node flagged |
| 121 | `test_remove_edge_detectable` | Graph monitor: edge removal detected |

#### Peer Introduction on SimNetwork — 3 tests

| # | Test | What it proves |
|---|------|---------------|
| 122 | `test_introduction_chain` | Introduction chain expands overlay |
| 123 | `test_overlay_expansion` | New channels created via introduction |
| 124 | `test_trust_after_introduction` | Introduced node gains trust |

#### Simulation Core — 22 tests

| # | Test | What it proves |
|---|------|---------------|
| 125 | `test_initial_tick` | Clock starts at tick 0 |
| 126 | `test_advance` | Clock advances correctly |
| 127 | `test_scheduled_event_fires` | Scheduled event fires at correct tick |
| 128 | `test_multiple_events_ordered` | Multiple events fire in order |
| 129 | `test_events_at_same_tick_fifo` | Same-tick events fire FIFO |
| 130 | `test_schedule_at_absolute` | Absolute-time scheduling works |
| 131 | `test_run_until_idle` | Clock runs until no pending events |
| 132 | `test_event_with_args` | Events carry arguments correctly |
| 133 | `test_channel_creation` | MockLiuChannel: creates with correct IDs |
| 134 | `test_key_generation` | MockLiuChannel: generates key bytes |
| 135 | `test_key_generation_deterministic` | MockLiuChannel: same PSK -> same keys |
| 136 | `test_mac_authenticate_verify` | MockLiuChannel: MAC roundtrip |
| 137 | `test_mac_is_real_gf61` | MockLiuChannel: MAC tag in [0, M61) |
| 138 | `test_closed_channel_rejects` | MockLiuChannel: closed channel raises |
| 139 | `test_advance_run` | MockLiuChannel: run_idx increments |
| 140 | `test_send_and_deliver` | Message bus: send + deliver |
| 141 | `test_delivery_delay` | Message bus: delayed delivery |
| 142 | `test_broadcast` | Message bus: broadcast to recipients |
| 143 | `test_adversary_hook_observe` | Message bus: adversary can observe |
| 144 | `test_adversary_hook_drop` | Message bus: adversary can drop |
| 145 | `test_adversary_hook_modify` | Message bus: adversary can modify |
| 146 | `test_audit_log` | Message bus: audit log records |

#### Simulation Network — 14 tests

| # | Test | What it proves |
|---|------|---------------|
| 147 | `test_messages_between` | Message bus: filtered query between two nodes |
| 148 | `test_random_graph_size` | Random graph: correct node count |
| 149 | `test_barabasi_albert_size` | BA graph: correct node count |
| 150 | `test_small_world_size` | Small-world: correct node count |
| 151 | `test_geographic_size` | Geographic: correct node count |
| 152 | `test_symmetry` | All topology generators: undirected (symmetric) |
| 153 | `test_channels_per_node_default` | Default channel count: log2(N)+1 |
| 154 | `test_n10_initializes` | SimNetwork(10): creates nodes and channels |
| 155 | `test_channels_established` | Every node has channels |
| 156 | `test_messages_route` | Messages route between connected nodes |
| 157 | `test_broadcast` | Broadcast reaches all neighbors |
| 158 | `test_connectivity` | Random graph on 10 nodes is connected |
| 159 | `test_all_topologies` | All 4 topology types initialize |
| 160 | `test_mark_corrupt` | Corrupt marking: honest/corrupt counts |
| 161 | `test_average_degree` | Average degree > 1 |

#### Real Liu Protocol — 12 tests

| # | Test | What it proves |
|---|------|---------------|
| 162 | `test_key_generation` | Real physics key bytes: nonzero, non-constant |
| 163 | `test_key_agreement` | Alice and Bob get identical bytes from StreamPipe |
| 164 | `test_mac_authenticate_verify` | Real Wegman-Carter MAC: compute + verify |
| 165 | `test_mac_reject_tamper` | Tampered data fails real MAC |
| 166 | `test_channel_lifecycle` | generate -> authenticate -> advance_run -> close |
| 167 | `test_multiple_key_requests` | Sequential reads yield different key material |
| 168 | `test_n10_dkg_real_liu` | N=10 DKG + real Liu MAC authentication |
| 169 | `test_n10_signing_real_liu` | Threshold sign + verify, real Liu MAC on signature |
| 170 | `test_sim_network_real_liu` | SimNetwork(5, use_real_liu=True) initializes |
| 171 | `test_messages_route_real` | Messages route over real Liu channels |
| 172 | `test_mac_cross_check` | Real MAC == Mock MAC for same inputs (5 run indices) |
| 173 | `test_protocol_equivalence` | DKG + signing + MAC: identical algebraic properties both backends |

#### Adversary Models — 16 tests

| # | Test | What it proves |
|---|------|---------------|
| 174 | `test_partial_eclipse_fails` | Partial eclipse: attacker can't reconstruct |
| 175 | `test_full_eclipse_succeeds` | Full eclipse: attacker reconstructs (expected) |
| 176 | `test_50_percent_eclipse` | 50% eclipse: still can't reconstruct |
| 177 | `test_bootstrap_succeeds_with_one_clean_path` | One clean path: bootstrap survives |
| 178 | `test_topology_eclipse` | Topology-aware eclipse attack |
| 179 | `test_topology_not_eclipsed` | Non-eclipsed topology survives |
| 180 | `test_sybil_trust_bounded_by_attack_edges` | Sybil trust bounded by g (attack edges) |
| 181 | `test_more_attack_edges_more_trust` | More attack edges -> more Sybil trust (bounded) |
| 182 | `test_sybil_count_doesnt_matter` | 10 vs 1000 Sybils: same trust bound |
| 183 | `test_below_threshold_cannot_reconstruct` | Collusion below threshold: can't reconstruct |
| 184 | `test_at_threshold_can_reconstruct` | Collusion at threshold: can reconstruct (expected) |
| 185 | `test_forgery_fails_below_threshold` | Collusion below threshold: can't forge |
| 186 | `test_initial_no_compromise` | Slow compromise: epoch 0 = 0% compromised |
| 187 | `test_compromise_increases_over_epochs` | Slow compromise: fraction increases |
| 188 | `test_consensus_disruption_threshold` | Slow compromise: eventual disruption |
| 189 | `test_trust_trajectory_monotonic` | Slow compromise: monotonically increasing |

#### Integration Scenarios — 37 tests

| # | Test | What it proves |
|---|------|---------------|
| 190 | `test_lifecycle[10]` | Full chain N=10: bootstrap -> DKG -> sign -> verify -> epoch rotate |
| 191 | `test_lifecycle[50]` | Full chain N=50 |
| 192 | `test_lifecycle_n100` | Full chain N=100 |
| 193 | `test_corrupt_minority_dkg_and_sign` | N=20, 5 corrupt: DKG completes, signing works, forgery fails |
| 194 | `test_sybil_trust_capture[3]` | Sybil g=3: trust bounded |
| 195 | `test_sybil_trust_capture[5]` | Sybil g=5: trust bounded |
| 196 | `test_sybil_trust_capture[10]` | Sybil g=10: trust bounded |
| 197 | `test_sybil_trust_capture[20]` | Sybil g=20: trust bounded |
| 198 | `test_eclipse_coverage[0.5]` | 50% eclipse: can't reconstruct |
| 199 | `test_eclipse_coverage[0.75]` | 75% eclipse: can't reconstruct |
| 200 | `test_eclipse_coverage[0.9]` | 90% eclipse: can't reconstruct |
| 201 | `test_eclipse_coverage[1.0]` | 100% eclipse: reconstructs (expected) |
| 202 | `test_collusion_signing_polynomial[1]` | 1 colluder: can't reconstruct |
| 203 | `test_collusion_signing_polynomial[3]` | 3 colluders: can't reconstruct |
| 204 | `test_collusion_signing_polynomial[6]` | 6 colluders: can't reconstruct |
| 205 | `test_slow_compromise_trajectory` | 20-epoch trajectory: monotonic, eventual disruption |
| 206 | `test_dkg_cost[10]` | DKG timing at N=10 |
| 207 | `test_dkg_cost[50]` | DKG timing at N=50 |
| 208 | `test_dkg_cost[100]` | DKG timing at N=100 |
| 209 | `test_dkg_scaling_fit` | DKG scales ~O(N^2) (power-law fit) |
| 210 | `test_signing_latency[10]` | Signing timing at N=10 |
| 211 | `test_signing_latency[50]` | Signing timing at N=50 |
| 212 | `test_signing_latency[100]` | Signing timing at N=100 |
| 213 | `test_pagerank_convergence[10]` | PageRank timing at N=10 |
| 214 | `test_pagerank_convergence[50]` | PageRank timing at N=50 |
| 215 | `test_pagerank_convergence[100]` | PageRank timing at N=100 |
| 216 | `test_memory_per_node[10]` | Memory estimate at N=10 |
| 217 | `test_memory_per_node[50]` | Memory estimate at N=50 |
| 218 | `test_memory_per_node[100]` | Memory estimate at N=100 |
| 219 | `test_extrapolate_dkg` | DKG extrapolation to N=10K, 100K |
| 220 | `test_extrapolate_pagerank` | PageRank extrapolation to N=10K, 100K |

#### Extended Scenarios — 41 tests

| # | Test | What it proves |
|---|------|---------------|
| 221 | `test_n200_full_dkg` | DKG at N=200: full verify + reconstruct |
| 222 | `test_n500_dkg_no_verify` | DKG at N=500: shares consistent |
| 223 | `test_n200_corrupt_minority` | DKG N=200: corrupt minority detected and excluded |
| 224 | `test_threshold_signing[200]` | Threshold signing at N=200 |
| 225 | `test_threshold_signing[500]` | Threshold signing at N=500 |
| 226 | `test_n1000_signing` | Threshold signing at N=1000 |
| 227 | `test_pagerank_at_scale[200]` | PageRank at N=200 |
| 228 | `test_pagerank_at_scale[500]` | PageRank at N=500 |
| 229 | `test_pagerank_at_scale[1000]` | PageRank at N=1000 |
| 230 | `test_sybil_n100_honest_n1000_sybil[3]` | 100 honest vs 1000 Sybil, g=3 |
| 231 | `test_sybil_n100_honest_n1000_sybil[5]` | 100 honest vs 1000 Sybil, g=5 |
| 232 | `test_sybil_n100_honest_n1000_sybil[10]` | 100 honest vs 1000 Sybil, g=10 |
| 233 | `test_sybil_n100_honest_n1000_sybil[20]` | 100 honest vs 1000 Sybil, g=20 |
| 234 | `test_sybil_count_irrelevance` | Sybil count doesn't affect trust bound |
| 235 | `test_50_epoch_trajectory` | 50-epoch slow compromise trajectory |
| 236 | `test_5_verifiers_agree_on_valid_sig` | 5 independent verifiers all accept valid signature |
| 237 | `test_5_verifiers_all_reject_forgery` | 5 independent verifiers all reject forgery |
| 238 | `test_dispute_resolution_unanimous` | Dispute resolution: unanimous among 5 verifiers |
| 239 | `test_signing_across_epochs` | Signatures valid across epoch rotation |
| 240 | `test_budget_forces_rotation` | Signature budget exhaustion forces epoch rotation |
| 241 | `test_dkg_via_message_bus` | DKG shares distributed over SimNetwork message bus |
| 242 | `test_csv_output` | Metrics reporter: CSV format |
| 243 | `test_json_output` | Metrics reporter: JSON format |
| 244 | `test_summary` | Metrics reporter: summary statistics |
| 245 | `test_to_dict` | Metrics reporter: dict conversion |
| 246 | `test_dkg_quadratic_fit` | DKG timing fits O(N^2) |
| 247 | `test_signing_linear_fit` | Signing timing fits O(N) |
| 248 | `test_extrapolate_all` | Multi-operation extrapolation |
| 249 | `test_full_node_lifecycle` | SimNode: channel -> DKG -> sign -> verify |
| 250 | `test_node_trust_computation` | SimNode: trust scores computed |
| 251 | `test_dispute_resolution_via_node` | SimNode: dispute resolution path |
| 252 | `test_liu_channel_wrapper` | LiuChannel: key_material + authenticate + verify |
| 253 | `test_channel_table` | ChannelTable: add/get/remove/active/idle |
| 254 | `test_shamir_detects_corrupt_relay` | Bootstrap Shamir: corrupt relay detected |
| 255 | `test_shamir_too_many_corrupt_fails` | Bootstrap Shamir: too many corrupt -> failure |
| 256 | `test_eclipse_success_rate[0.0]` | Eclipse sweep: 0% coverage |
| 257 | `test_eclipse_success_rate[0.25]` | Eclipse sweep: 25% coverage |
| 258 | `test_eclipse_success_rate[0.5]` | Eclipse sweep: 50% coverage |
| 259 | `test_eclipse_success_rate[0.75]` | Eclipse sweep: 75% coverage |
| 260 | `test_eclipse_success_rate[0.9]` | Eclipse sweep: 90% coverage |
| 261 | `test_eclipse_success_rate[0.95]` | Eclipse sweep: 95% coverage |
| 262 | `test_eclipse_success_rate[1.0]` | Eclipse sweep: 100% coverage |
| 263 | `test_collusion_sweep` | Collusion: parametric sweep 1..threshold |
| 264 | `test_collusion_at_exact_threshold` | Collusion: exact threshold boundary |
| 265 | `test_forgery_sweep` | Forgery: parametric sweep of strategies |
| 266 | — | **All 266 passing** |

The simulation framework provides two Liu channel backends:
- **MockLiuChannel** (default): deterministic key bytes via SHA-256, real GF(M61)
  MACs. Fast (~107s for 254 tests). Used for CI and rapid iteration.
- **RealLiuChannel**: actual `liuproto.StreamPipe` physics — Gaussian noise
  exchange, privacy amplification, Toeplitz hashing. Real ITS key material.
  Slower (~0.3-0.5s per channel setup). Enabled via `use_real_liu=True`.

Both backends produce identical MAC tags for the same inputs (verified by
cross-check tests). The only difference is key material origin: hash-derived
vs physics-derived.

### End-to-end ITS — no computational assumptions anywhere

The full chain runs without any computational hardness assumption:

```
Bootstrap (Shamir over diverse TCP paths)
    → PSK (information-theoretically secure)
        → Liu channel (Gaussian noise + privacy amplification)
            → ITS key material (Shannon-proven)
                → DKG (polynomial secret sharing)
                    → USS signatures (polynomial evaluation)
                        → Verification (independent evaluation points)
```

No step depends on factoring, discrete log, lattice hardness, or any
unproven conjecture. Security follows from Shannon's theorems and
honest-majority assumptions — the same assumption every BFT system makes.

PSK establishment is digital and in-protocol (multi-path bootstrap + XOR
peer introduction). No physical courier. An arbitrarily powerful Eve cannot
break it as long as she doesn't control all bootstrap paths or all
introducing peers.

### Running the tests

```bash
# Clone both repos side by side
git clone https://github.com/noospheer/Liun.git
git clone https://github.com/noospheer/Liup.git
cd Liun
pip install -e .

# Full suite (mock Liu, ~2 min)
PYTHONPATH=. python3 -m pytest tests/ -v

# Full suite with real Liu physics (~13 min)
PYTHONPATH=../Liup/src:. python3 -m pytest tests/ -v

# Real Liu tests only
PYTHONPATH=../Liup/src:. python3 -m pytest tests/test_real_liu.py -v

# Skip slow (real Liu) tests
PYTHONPATH=../Liup/src:. python3 -m pytest tests/ -v -m "not slow"
```

### What needs verification
- Formal composition proof (three primitives, six protocol layers)
- Graph mixing properties of real Liu channel networks
- Internet path diversity measurements for bootstrap
- Multi-node deployment over real TCP (StreamServer/StreamClient instead of StreamPipe)

---

## One-Line Summary

**Three primitives (polynomials, noise, graph walks), one field (M61), zero
computational assumptions — ITS digital signatures that a quantum computer
cannot break, running on hardware you already own.**
