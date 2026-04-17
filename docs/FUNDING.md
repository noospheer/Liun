# Funding: the public-goods pool

How Liun operators get paid for the work their nodes do, without
stake, fees, pubkeys, or a committee.

## One role, one binary, one wallet

```
$ liun-node init --payout 0xabc...
$ systemctl enable --now liun-node
```

That's it. You're serving traffic. ETH arrives weekly. No "node vs
aggregator" distinction to manage — the daemon handles everything.

## Three layers

```
┌──────────────────────────────────────────────────────────────────┐
│  Ethereum mainnet  —  LiunPool.sol                               │
│    deposit()    postEpoch(root, budget) + deposit                │
│    invalidateEpoch(altRoot)   finalize()   claim(proof)          │
│    Any node publishes; gas refunded; 7-day challenge window.     │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Merkle root — computed by any node
                              │ from public blob data + public trust graph
┌──────────────────────────────────────────────────────────────────┐
│  Tally  —  liun-tally crate                                      │
│    Pure function:  (claims ∪ blobs, trust, addr_book) → Merkle   │
│    Any node can re-run. Deterministic.                           │
│    Pairs client+server by session_id; credits min(both totals);  │
│    requires BOTH parties to have positive public trust.          │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ per-node ClaimBatch, posted as
                              │ EIP-4844 blob at epoch close
┌──────────────────────────────────────────────────────────────────┐
│  Nodes  —  liun-receipts crate (OpRecorder)                      │
│    Every session: both endpoints track bytes/ops locally, MAC    │
│    a single ReceiptClaim under the SharedKey they already have   │
│    from the Liu channel between them. NO wire overhead on the    │
│    data path. At epoch close each node posts ITS OWN batch.      │
└──────────────────────────────────────────────────────────────────┘
```

## How money flows

1. **Deposit.** Anyone funds the pool with ETH. No ERC-20, no token
   economics, no minting.

2. **Work happens.** Nodes serve traffic (relay shares, DHT queries,
   Liu channel bytes). Each session's endpoints track a running byte
   count off the data path.

3. **Epoch close.** Each node independently signs a `ClaimBatch` of
   its own sessions (both its client-side claims and its server-side
   claims) and posts it as an EIP-4844 blob. ~$0.01 per blob. O(N)
   blobs per epoch — tiny on a DA layer.

4. **Tally.** Any node reads all blobs + the public trust graph and
   runs `liun-tally::tally`. Output is a deterministic ordered list of
   `(nodeId, payoutAddr, amountWei)` and its Merkle root. Every node
   gets the same root because all inputs are public.

5. **Publish.** The first node whose publish-timer fires submits the
   root to `LiunPool.postEpoch(epoch, root, budget)` with a small
   anti-spam deposit (e.g. 0.01 ETH). Gas cost ~150k. Any later
   submitter's call reverts.

6. **Challenge window.** Seven days. Anyone who re-runs the tally and
   gets a different root calls `invalidateEpoch(epoch, altRoot)`.
   Publisher's deposit is split: half to the challenger, half burned.
   The epoch is dead; nobody gets paid that week. Operators see the
   disagreement off-chain, debug it, and move on to the next epoch.

7. **Finalization.** After 7 days with no challenge, the publisher's
   deposit is returned and a small gas refund is paid off the top of
   the epoch budget. Publisher is net-zero economic.

8. **Claim.** Each node submits `claim(epoch, nodeId, payoutAddr,
   amount, proof)`. ETH is transferred directly.

## Why Sybils earn nothing

Trust is personalized PageRank over a public vouching graph seeded
from known honest parties (EF, foundations). The tally function
enforces that a session only counts toward payout if **both** the
client and the server have positive trust in the graph.

Consequences:

- A brand-new Sybil node has no inbound vouches → PageRank ≈ 0 →
  zero trust → every session it participates in is dropped.
- A trusted server colluding with a Sybil client to inflate its
  claim earns zero: the Sybil client's zero trust disqualifies the
  pair.
- Earning requires not just work but *trust-weighted* work. The only
  way to get trust is to be vouched for by someone who already has
  it. Trust can't be minted.

The vouching graph is public and anyone can compute the same trust
values — no gatekeeper.

## What's NOT here anymore

Earlier drafts of this design had:
- A privileged "aggregator" role with a keystore.
- A k-of-N committee signing tallies.
- An on-chain `AggregatorRegistry` with bonds and metadata.

All deleted. The tally is a pure function; publication is a volunteer
race with gas refund; trust is the sole Sybil defense.

## Why this stays ITS in the liuniverse

Computational crypto still appears only at the Ethereum boundary:
ECDSA for the publish+claim transactions, keccak for the Merkle tree.
Those are unavoidable as long as Ethereum is the chain.

Inside the Liun protocol:

- Receipts are Wegman-Carter MAC'd over GF(M61) with one-time-use
  keys from the Liu channel. Forgery bound ≤ 142/M61 ≈ 6.2 × 10⁻¹⁷
  per attempt.
- SharedKeys are peer-to-peer, derived from the Liu channel that
  already exists between any two interacting nodes. No out-of-band
  provisioning to a trusted custodian.
- No pubkeys anywhere in the receipt layer.

## Trust assumptions, honestly

| Assumption | What breaks if it's wrong |
|---|---|
| Seed parties for trust graph are distinct & non-colluding | Capturing them lets an attacker inject trusted Sybils |
| Ethereum mainnet secure | Contract balance or tally could be corrupted at the chain layer |
| Liu channel between each pair is ITS | Their pair's receipts could be forged if that channel's key stream leaks |
| ≥ 1 honest node reads blobs + submits a challenge when a wrong root is posted | A malicious publisher could push a bad root that goes unchallenged |

None of these compromise user **chat confidentiality or authenticity**.
If every assumption above fails simultaneously, the only thing lost
is correct payout attribution. User data stays ITS-secure.

## Performance posture

- **Pipeline courier:** replaces the round-trip Gaussian exchange
  with continuous bidirectional OTP-encrypted streaming. Single
  channel: ~5 Gbps (MAC-bound), ~10 Gbps with AVX-512. Wire
  overhead: 0.8%. Tested over real internet: 69 Mbps EC2↔local.
  Lean-4-proved including self-rekeying chain induction
  (`PipelineCourier.lean`, zero `sorry`): Eve's bias on every key
  in the chain = 0 for any number of chunks, proved by `Nat.rec`.
- **MAC throughput:** 625 M coefficients/sec (4-way parallel Horner).
- **Concurrent pool refill:** `SharedPool` lets N producer threads
  deposit into one pool under brief Mutex critical sections.
- **Idle-time pre-warming:** `PrewarmTracker` picks top-K peers to
  refill during idle windows.
- **Wire overhead on data path:** 0 bytes for receipts (off-path) +
  20 bytes per chat frame (packed 4-byte mux + 16 bytes MAC/ts). TLS
  comparable: 29 bytes.
- **Tested over real internet:** EC2 us-east-1 ↔ local, 21ms latency,
  100% MAC verification, 43 exchange rounds, pool self-sustaining.

## Hook points in the code

- **Relay:** `liun-overlay::relay_server::serve_with_recorder(addr,
  recorder, epoch)`. Client advertises its NodeId in the
  `X-Liun-Client-Id` HTTP header only; no receipt traffic on the wire.
- **DHT:** `DhtNode::start_with_recorder(config, Some(hook))`. Each
  handled PING/FIND credits one op to a long-running session with the
  requester.
- **Channel:** `Channel::with_receipt_hook(hook)`. Each `run_batch`
  credits `batch_size / 8` bytes to the peer's long-running session.

## References

- Receipt types + WC MAC: `crates/liun-receipts/src/lib.rs`
- Claim wire format: `SignedClaim::to_wire` / `from_wire`
- Off-path recorder: `crates/liun-receipts/src/recorder.rs`
- Tally algorithm (session pairing + trust filtering):
  `crates/liun-tally/src/lib.rs`
- Pool contract: `contracts/src/LiunPool.sol`
- Forge tests: `contracts/test/LiunPool.t.sol` (16 tests, all pass)
- e2e flow demos: `crates/liun-receipts/tests/e2e_op_flow.rs`,
  `crates/liun-overlay/tests/relay_receipts.rs`,
  `crates/liun-dht/tests/dht_receipts.rs`
- Trust / PageRank (federated seeds): `crates/liun-overlay/src/trust.rs`
