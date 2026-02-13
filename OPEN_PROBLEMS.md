# Liun Open Problems

## 1. Sybil Resistance Without Computation [SOLVED — NEEDS VERIFICATION]

**The problem:** Every decentralized system needs Sybil resistance — a mechanism
to prevent one adversary from creating unlimited fake identities. Existing
solutions all use either computational cost (PoW) or economic cost (PoS),
which introduce the computational assumptions we're trying to eliminate.

**Why it matters:** If Eve can cheaply create fake nodes, she breaks the honest
majority assumption that the entire system depends on.

**Solution: Local Trust via Personalized PageRank on Liu Channel Graph**

The key insight: voting weight isn't one-node-one-vote — it's trust flow
through Liu channels. Each node computes trust from its own position in the
Liu channel graph using personalized PageRank (random walk with restart).

- No founding members. No global authority. Each node is its own trust seed.
- Trust is local, subjective, and emergent.
- Sybil resistance: an attacker's trust is bounded by their **attack edges**
  (connections to honest nodes), regardless of how many fake nodes they create.
- Proven by SybilRank (Yu et al. 2006): total trust flowing to a Sybil
  region is O(attack edges), not O(Sybil nodes).

**Why it works without computation:**
- Random walk is arithmetic (matrix-vector multiply), not a hardness assumption
- Liu channels provide the graph structure (real bandwidth = real edges)
- No PoW, no PoS, no currency, no gate-keeping

**What still needs verification:**
- Fast mixing properties of real Liu channel graphs (do they mix well enough
  for PageRank to converge quickly?)
- Behavior under sustained slow infiltration (attacker gradually builds
  legitimate channels over months)
- Formal proof that local trust composes correctly with USS threshold signing
- Optimal damping factor and walk length for Liun graph topologies

See: [protocols/06-local-trust.md](protocols/06-local-trust.md)

**Status:** Proposed solution. Theoretical basis is strong (SybilRank has
formal proofs). Needs empirical validation on realistic Liu channel networks.

---

## 2. Bootstrap Window Minimization [MEDIUM]

**The problem:** The initial bootstrap (Phase 0) is the only part of the
protocol that depends on network topology. The default multi-path bootstrap
takes ~5 minutes. How do we harden this window?

**Current default:** ~5 minutes. Node selects 20 geographically diverse
existing nodes, sends Shamir-encoded shares via independent routes, establishes
Liu channels, begins peer introductions. Fully operational in minutes.

**Optional hardening approaches:**

1. **Temporal diversity**: Bootstrap from different network contexts over
   multiple sessions (home, office, cafe, mobile). Maximizes route
   independence but is NOT required for basic operation.

2. **Network flooding**: All nodes blast cover traffic during bootstrap
   events. Hides the real shares in noise. Bandwidth-intensive.

3. **Bounded storage model**: If nodes collectively broadcast more random
   data than Eve can store in real-time, shared secrets can be extracted
   ITS. Requires high aggregate bandwidth.

4. **One-time PSK (minimum viable bootstrap)**: Accept ONE physical
   secret exchange (USB stick, QR code printed on paper, whispered
   passphrase). 12.5 KB of data. This is O(1) physical interaction,
   then purely digital forever. The PSK seeds one Liu channel, and
   peer introduction expands to the full network.

5. **ECDH bootstrap with everlasting security**: Use computational crypto
   for a 30-second handshake, then transition to ITS. The computational
   assumption is confined to a one-time, seconds-long window.

**Research question:** Can we prove a lower bound on the bootstrap
assumption? Is there a construction that achieves ITS bootstrap over a
fully observed single channel? (Likely not — Shannon.)

---

## 3. Optimal Path Selection [MEDIUM]

**The problem:** Multi-path XOR security depends on actual route
independence. Internet paths may share infrastructure (IXPs, submarine
cables, Tier-1 ISPs) in ways that aren't visible to the endpoints.

**Research directions:**
- Internet topology mapping for path independence estimation
- Latency-based path verification (detect route convergence)
- Jurisdiction-aware routing (ensure paths cross non-cooperating states)
- Collaboration with network measurement projects (RIPE Atlas, CAIDA)

---

## 4. Epoch Transition Protocol [MEDIUM]

**The problem:** USS signing polynomials have bounded signature budgets
(~degree/2 signatures before key material is exhausted). Periodic re-dealing
is required. How to transition seamlessly without downtime?

**Requirements:**
- Old polynomial remains valid until new one is fully distributed
- No signing gap during transition
- New members joining mid-epoch get current polynomial shares
- Liu provides fresh key material for each re-deal

**Approach:** Overlapping epochs with grace period. New polynomial
generated and distributed while old one is still active. Cutover at
a pre-agreed block/timestamp.

---

## 5. Scale Testing [MEDIUM]

**The problem:** All security arguments are asymptotic. Need empirical
validation at realistic network sizes.

**Milestones:**
- 10 nodes (local testbed): Verify correctness of full protocol chain
- 100 nodes (LAN/WAN): Measure Liu throughput under concurrent channels
- 1000 nodes (distributed): Stress-test overlay routing, DKG latency
- Adversarial testing: Inject Byzantine nodes, measure detection time

---

## 6. USS Polynomial Degree Optimization [LOW]

**The problem:** Higher polynomial degree = more signatures per epoch,
but also larger verification shares and slower DKG.

**Trade-off:**
- Degree d: ~d/2 signatures before re-deal
- Share size: O(d) field elements per verifier
- DKG communication: O(N * d) over ITS channels
- Verification time: O(d) polynomial evaluation

**Question:** What's the sweet spot for d given realistic N and signing rates?

---

## 7. Formal Security Proof [LOW PRIORITY, HIGH VALUE]

**The problem:** The security argument is currently informal (this design
document). A formal proof in the Universal Composability (UC) framework
would provide the strongest possible guarantee.

**Proof components needed:**
- Multi-path XOR key agreement: security in bounded eavesdropping model
- Peer introduction: composable security from pairwise ITS channels
- Shamir DKG: ITS security with honest majority
- USS: ITS unforgeability and non-repudiation
- Composition: the full chain maintains ITS under concurrent operation
