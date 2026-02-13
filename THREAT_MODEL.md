# Liun Threat Model

## 1. Adversary Model

Eve is an adversary who may:
- Passively observe network traffic on links she has access to
- Actively control up to t < N/3 network nodes (Byzantine)
- Have **unbounded computational power** (including quantum computers)
- Record and store observed traffic indefinitely

Eve may NOT:
- Read the RAM of honest nodes (universal assumption in all cryptography)
- Violate the laws of physics (speed of light, thermodynamics)
- Simultaneously observe all internet routes between all pairs of nodes

---

## 2. Attack Analysis

### 2.1 Eclipse Attack

**Severity: CRITICAL (bootstrap only)**

Eve IS the target node's ISP. All "diverse" paths exit through Eve's router.
Eve sees all bootstrap shares.

```
    A --path 1--+
    A --path 2--+
    A --path 3--+--> [Eve's router] --> internet
    ...         |
    A --path 20-+

    Eve sees ALL shares. Bootstrap broken.
```

**Scope:** Bootstrap phase ONLY. Once ITS overlay is established, all
secret material travels over ITS channels (encrypted + authenticated).
Eve sees ciphertext she cannot break (ITS encryption via Liu OTP).

**Mitigations:**
- **Temporal diversity**: Bootstrap from different network contexts over
  days (home, office, cafe, mobile). Eve must control ALL contexts.
- **Network flooding**: Existing nodes blast random cover traffic during
  bootstrap, raising the cost of targeted surveillance.
- **One-time PSK**: Accept one physical PSK exchange (USB stick, QR code)
  as the absolute minimum bootstrap. O(1) physical interaction, then
  purely digital forever.
- **Computational bootstrap (optional)**: Use ECDH for initial 30-second
  handshake, then transition to ITS. Reduces to everlasting security —
  Eve must break ECDH in real-time during those 30 seconds.

**Post-bootstrap:** Eclipse attack is IRRELEVANT. ITS overlay provides
authenticated encrypted channels regardless of network topology.

---

### 2.2 Sybil Attack

**Severity: HIGH (mitigated by local trust)**

Eve creates many fake nodes to try to break honest majority.

```
    Real network: 100 honest nodes
    Eve adds:     1000 fake nodes

    Naive one-node-one-vote: Eve has 91% of votes. BROKEN.
    Local trust (PageRank):  Eve's trust bounded by attack edges.
                             1000 Sybils with 3 attack edges ≈ 3 honest nodes' trust.
                             NOT BROKEN.
```

**Solution: Local Trust via Personalized PageRank**

Voting weight is NOT one-node-one-vote. Each node computes trust via random
walk on the Liu channel graph (personalized PageRank with restart). Trust
flows through real Liu channels — which require real bandwidth and real PSKs.

Key properties:
- Eve's total trust is bounded by her **attack edges** (connections to honest
  nodes), regardless of how many fake nodes she creates
- Each node computes trust independently from its own perspective — no global
  authority, no founding members
- Proven by SybilRank (Yu et al. 2006)

**Residual risk:** Slow infiltration — Eve gradually builds legitimate
channels with honest nodes over months, increasing her attack edges. This is
bounded by honest nodes' willingness to form new channels and is detectable
by graph monitoring.

**Scope with mitigation:** Eve needs O(honest nodes) attack edges to
meaningfully influence consensus, requiring long-term social engineering
at scale. Same difficulty as attacking any social network.

See: [protocols/06-local-trust.md](protocols/06-local-trust.md)

---

### 2.3 BGP Hijack

**Severity: HIGH (bootstrap only)**

Eve announces false BGP routes, causing A's "diverse" paths to converge
through Eve's infrastructure.

**Scope:** Bootstrap phase only. Post-overlay, secrets don't travel over
raw TCP.

**Mitigations:**
- RPKI and BGP monitoring (infrastructure-level, not protocol-level)
- Path validation via traceroute/latency analysis during bootstrap
- Temporal diversity (BGP hijacks are detectable and time-limited)
- Multiple bootstrap sessions from different origins

---

### 2.4 Chokepoint Surveillance

**Severity: HIGH (bootstrap only)**

The internet has physical chokepoints: submarine cables, IXPs, Tier-1 ISPs.
20 "diverse" paths may converge at shared infrastructure.

```
    Path 1:  US --> [submarine cable A] --> Europe
    Path 5:  US --> [submarine cable A] --> Asia     <-- same cable
    Path 12: US --> [submarine cable B] --> Africa

    Eve taps 3 cables --> sees 15 of 20 paths
```

**Scope:** Bootstrap only. Post-overlay, irrelevant.

**Mitigations:**
- Path selection must account for actual internet topology
- Avoid paths sharing submarine cables, IXPs, or Tier-1 transit
- Use nodes in jurisdictions with non-cooperating surveillance regimes
- Increase k (more paths = more taps needed)

---

### 2.5 Collusion Amplification

**Severity: MODERATE**

Eve controls t < k/3 corrupt nodes. Those nodes share their received
shares with Eve, reducing the number of paths Eve must passively surveil.

```
    k = 20 paths
    Eve controls 6 nodes (within 1/3 limit)
    Eve gets 6 shares for free
    Now only needs to passively observe 14 remaining paths
```

**Mitigation:** Increase k proportionally. Use more introducers for
peer introduction than strictly required.

---

### 2.6 Traffic Analysis

**Severity: MODERATE**

Even without reading content, Eve observes timing, volume, and connection
patterns to identify bootstrap sessions and target surveillance.

**Mitigations:**
- Traffic padding and decoy connections during bootstrap
- Batched/delayed bootstrap (don't connect to all k nodes simultaneously)
- Network-wide cover traffic

---

### 2.7 Slow Compromise

**Severity: MODERATE (long-term)**

Eve gradually compromises nodes over months/years through hacking, coercion,
or purchase. Eventually crosses the 1/3 threshold.

**Mitigations:**
- Node rotation and periodic re-keying
- Monitoring for compromised behavior (Byzantine fault detection)
- Growing the honest node set faster than Eve can compromise

**Note:** This threat is identical for ALL decentralized systems (Bitcoin,
Ethereum, etc.). Not specific to Liun.

---

## 3. Attack Surface Timeline

```
BOOTSTRAP (minutes, one-time):
|
|  Eclipse ................ CRITICAL
|  BGP hijack ............ HIGH
|  Chokepoint surveillance  HIGH
|  Traffic analysis ....... MODERATE
|  Collusion amplification  MODERATE
|
OVERLAY ESTABLISHED (forever after):
|
|  Eclipse ................ IRRELEVANT (ITS channels)
|  BGP hijack ............ IRRELEVANT (ITS channels)
|  Chokepoint surveillance  IRRELEVANT (ITS channels)
|  Traffic analysis ....... LOW (encrypted traffic only)
|  Collusion amplification  LOW (introductions use multiple intermediaries)
|
ALL PHASES:
|
|  Sybil ................. MITIGATED (local trust bounds attack edges)
|  Slow compromise ....... MODERATE (same as all decentralized systems)
|  Slow infiltration ..... MODERATE (bounded by channel capacity)
|  Quantum computers ..... IRRELEVANT (nothing to compute)
|  Mathematical advances .. IRRELEVANT (information-theoretic)
```

---

## 4. Comparison: What Breaks What

| Attack | ECDSA | QKD Signatures | Liun |
|--------|-------|---------------|---------|
| Quantum computer | TOTAL BREAK | No effect | No effect |
| Record-decrypt-later | TOTAL BREAK | No effect | No effect |
| New factoring algorithm | TOTAL BREAK | No effect | No effect |
| Eclipse/MITM (bootstrap) | Breaks without CA | N/A (physical) | Breaks bootstrap only |
| Sybil (>1/3 trust) | N/A (no majority needed) | N/A | Bounded by attack edges (local trust) |
| Global passive observer | No effect (ECDH is public) | No effect | Breaks bootstrap only |
| Node compromise (>1/3) | No effect | No effect | TOTAL BREAK |
