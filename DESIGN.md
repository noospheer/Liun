# Liun: Decentralized Information-Theoretically Secure Digital Signatures

## 1. Overview

Liun is a protocol suite that achieves **fully decentralized digital signatures
with information-theoretic security** (ITS) over standard internet infrastructure.
No quantum hardware. No special hardware. No computational hardness assumptions
for ongoing operation.

It is built on top of the [Liu protocol](../Liup/) (`liuproto`), which provides
ITS symmetric key agreement and expansion from a pre-shared key (PSK).

### 1.1 What Liun Achieves

| Property | Status |
|----------|--------|
| ITS unforgeability | Yes — polynomial interpolation threshold |
| Multi-party verification | Yes — each verifier checks independently |
| Non-repudiation | Yes — independent verification shares, majority adjudication |
| No trusted dealer | Yes — Shamir distributed key generation |
| No privileged nodes | Yes — all nodes symmetric, threshold signing |
| Permissionless joining | Yes — multi-path bootstrap + peer introduction |
| Dynamic membership | Yes — join/leave at epoch boundaries |
| No special hardware | Yes — standard CPU, standard TCP/IP |
| No computational assumptions (post-bootstrap) | Yes |

### 1.2 Core Insight

Shannon (1949) proved that two parties sharing no prior secret cannot establish
one over a single public channel against an unbounded eavesdropper. But the
internet is **not** a single channel — it is a network of thousands of
independent physical routes. By exploiting this topological diversity, and by
building an ITS overlay network that becomes self-sustaining after initial
bootstrap, we achieve a fully ITS chain:

```
Multi-path XOR          Shamir          Liu            USS
(ITS key agreement) --> (ITS sharing) --> (ITS key gen) --> (ITS signatures)
     |                     |              |               |
Network diversity    Honest majority   PSK from      ITS channels
(physical)          (standard)        Phase 1+2     from Phase 3
```

### 1.3 Assumptions

| # | Assumption | Type | Comparable to |
|---|-----------|------|---------------|
| 1 | Honest majority (>2/3 of trust-weighted nodes) | Standard | Bitcoin, Ethereum, all PoS |
| 2 | Network route diversity for initial bootstrap | Physical | NOT computational — strengthens as internet grows |
| 3 | Honest nodes have private memory | Universal | Every cryptographic system assumes this |

No computational hardness. No special hardware. No quantum mechanics.

---

## 2. Architecture

### 2.1 Components

| Component | What it does | ITS? | Implemented in |
|-----------|-------------|------|----------------|
| Multi-path XOR | Key agreement between strangers | Yes (bounded eavesdropping) | `bootstrap.py` |
| Shamir secret sharing | Splits secrets, tolerates corrupt nodes | Yes (unconditional) | `dkg.py` |
| Liu protocol | Expands small key into unlimited key stream | Yes (Gaussian + MAC over M61) | `liuproto` (external) |
| USS (polynomial-based) | Asymmetric signatures from symmetric keys | Yes (polynomial interpolation) | `uss.py` |
| ITS overlay | Peer introduction, channel management | Yes (routed over ITS channels) | `overlay.py` |
| Local trust | Sybil resistance via personalized PageRank | Yes (arithmetic, no hardness) | `overlay.py` |

### 2.2 Three-Primitive Reduction

The entire system reduces to three primitives:

| Primitive | What it provides | Used for |
|-----------|-----------------|----------|
| **Polynomial arithmetic over GF(M61)** | One finite field operation | Shamir sharing, USS signing, Liu MAC |
| **Liu protocol (Gaussian noise)** | ITS key material from PSK | Key expansion, MAC authentication, sigma verification |
| **Random walk on channel graph** | Local trust computation | Sybil resistance, consensus weighting |

Everything else (bootstrap, DKG, peer introduction, epoch rotation, dispute
resolution) is **composition** of these three. Same algebraic operation
(polynomial evaluation), same field (M61 = 2^61 - 1), three applications.

### 2.3 Dependency Chain

```
its-net ---depends on---> liuproto
liuproto ---knows nothing about---> its-net
```

`liuproto` is the ITS key engine. Liun is the protocol layer that builds
decentralized signatures on top of it.

### 2.4 Layer Model

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

## 3. Protocol Phases

### Phase 0: Bootstrap (one-time, minutes)

New node A joins the network with no prior keys or relationships.

1. A selects k=20 existing nodes at random (geographically diverse)
2. For each node Bi, A generates random share ri (256 bits)
3. A sends ri to Bi via a DISTINCT network route
4. Shared secret with Bi: derived from ri
5. Multi-path XOR: Eve must observe ALL k routes to learn all shares

**Shamir protection against active adversaries:**
- Encode each secret into n shares via Shamir (k-of-n threshold)
- Route each share via independent path
- Corrupt relays (up to t < k/3) detected and discarded via consistency check
- Reconstruction succeeds from the k honest shares

**Temporal diversity option:** Bootstrap over multiple days from different
network contexts (home, office, cafe, mobile) to maximize route independence.

See: [protocols/01-bootstrap.md](protocols/01-bootstrap.md)

### Phase 1: ITS Channel Establishment

Turn bootstrap secrets into authenticated, reusable ITS channels.

1. Use each shared secret ri as PSK for the Liu protocol
2. Liu generates unlimited ITS key material from this seed
3. Wegman-Carter MAC over M61 authenticates all messages
4. Pool recycling means channels never expire

See: [protocols/05-liu-integration.md](protocols/05-liu-integration.md)

### Phase 2: Overlay Expansion (topology-independent)

Once A has ITS channels with k nodes, it can reach ANY node in the network
without ever touching raw TCP for secret material.

**Peer introduction protocol:**

A has ITS channels with B1, B2, B3. A wants a channel with C.

```
B1 generates random PSK1
   sends PSK1 to A over ITS channel A<->B1
   sends PSK1 to C over ITS channel B1<->C

B2 generates random PSK2
   sends PSK2 to A over ITS channel A<->B2
   sends PSK2 to C over ITS channel B2<->C

B3 generates random PSK3
   sends PSK3 to A over ITS channel A<->B3
   sends PSK3 to C over ITS channel B3<->C

A computes:  PSK_AC = PSK1 XOR PSK2 XOR PSK3
C computes:  PSK_AC = PSK1 XOR PSK2 XOR PSK3

A and C run Liu with PSK_AC --> ITS channel A<->C
```

**Corrupt introducer protection:** Bi knows PSKi but not the others. XOR of
all three is unknown to any single introducer. Honest majority ensures the
combined key is ITS-secure.

**Key property:** After this phase, network topology is IRRELEVANT. All
secrets travel over the ITS overlay, not raw TCP.

See: [protocols/02-peer-intro.md](protocols/02-peer-intro.md)

### Phase 3: Distributed Key Generation

Nodes collectively generate a threshold signing polynomial via Shamir DKG.

1. Each node contributes randomness over ITS channels
2. Each node receives one share of the collective signing polynomial
3. No single node ever sees the full polynomial
4. k-of-n threshold: any k nodes can sign, k-1 learn nothing

See: [protocols/03-shamir-dkg.md](protocols/03-shamir-dkg.md)

### Phase 4: Sign and Verify

**Signing** (threshold, k-of-n):
1. k nodes each compute partial signature using their share
2. Partial signatures combined into full USS signature sigma
3. Broadcast (m, sigma)

**Verification:**
- Any node checks sigma against their verification share
- Independent shares -> independent checks
- Adversary with < k shares cannot forge

**Non-repudiation:**
- Node X claims "A signed m" — Node Y disagrees
- Each checks against their own independent share
- Majority rules (honest majority assumption)
- ITS — no computation breaks this

See: [protocols/04-uss-signing.md](protocols/04-uss-signing.md)

---

## 4. Security Properties

### 4.1 Security at Each Link

| Step | Attack | Defense | ITS? |
|------|--------|---------|------|
| Multi-path key agreement | Eve observes routes | Must observe all k — miss one, zero info | Yes |
| Active relay corruption | Corrupt node modifies share | Shamir threshold — detect and discard | Yes |
| Liu key expansion | Eve eavesdrops TCP | Authenticated by PSK-derived MAC, OTP-encrypted | Yes |
| Signing polynomial distribution | Adversary wants full polynomial | Shamir DKG — k-1 shares reveal nothing | Yes |
| Signature forgery | Forge without enough shares | Polynomial interpolation requires k points | Yes |
| Non-repudiation dispute | Signer denies signing | Independent shares, majority adjudication | Yes |

### 4.2 What Does NOT Break This

| Attack | Effective? | Why |
|--------|-----------|-----|
| Quantum computer | No | Nothing to compute |
| Faster classical computers | No | No computational assumption |
| Mathematical breakthrough | No | Security is information-theoretic |
| Record-now-decrypt-later | No | No ciphertext to store and later break |
| Cryptanalysis | No | XOR with unknown uniform = perfect secrecy |

### 4.3 Bootstrap Window

The network topology assumption (bounded eavesdropping) applies ONLY to
the initial bootstrap (Phase 0). Once the ITS overlay is established
(Phase 2+), all channel establishment happens over ITS channels and
topology is irrelevant.

```
  +------------------+     +-------------------------------------+
  |  Bootstrap       |     |  Normal operation                   |
  |  (minutes, once) | --> |  (forever after)                    |
  |                  |     |                                     |
  |  Topology matters|     |  Topology IRRELEVANT                |
  |                  |     |  ITS overlay handles all routing    |
  +------------------+     +-------------------------------------+
```

See: [THREAT_MODEL.md](THREAT_MODEL.md) for full attack analysis.

---

## 5. Comparison with Existing Systems

### 5.1 vs Computational Signatures (ECDSA, RSA)

| Property | ECDSA | Liun |
|----------|-------|---------|
| Security basis | Discrete log hardness | Information theory |
| Quantum resistant | No | Yes (inherently) |
| Permissionless | Yes | Yes |
| Trusted setup | No | No (Shamir DKG) |
| Key agreement | ECDH (computational) | Liu (ITS) |
| Breaks with math advance | Yes | No |
| Requires honest majority | No | Yes |
| Network topology assumption | No | Bootstrap only |

### 5.2 vs QKD-based Signatures

| Property | QDS (quantum) | Liun |
|----------|--------------|---------|
| Security basis | Quantum mechanics | Network diversity + information theory |
| Special hardware | Quantum channels, SPDs | None — standard CPU + TCP/IP |
| Throughput | ~kbps | ~Mbps (Liu-limited) |
| Assumption type | Physical (QM is correct) | Physical (network diversity) |
| Permissionless | Limited | Yes |

### 5.3 vs Unconditionally Secure Signatures (USS, standard)

| Property | Standard USS | Liun |
|----------|-------------|---------|
| Trusted dealer | Required | Eliminated (Shamir DKG) |
| Key distribution | Pre-shared by dealer | Liu protocol (continuous) |
| Signature budget | Fixed, exhaustible | Renewable (Liu key recycling) |
| Decentralized | No | Yes |

---

## 6. Parameters

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| N (total nodes) | 100-1000 | Practical network size |
| k (signing threshold) | 2N/3 + 1 | Honest majority |
| Bootstrap paths | 20 | Across >=10 countries/ISPs |
| Liu B (bits per run) | 100,000 | Fits L3 cache, ~12.5 KB PSK |
| USS polynomial degree | ~1000 | Bounded signatures per epoch |
| Epoch length | ~1 hour | Re-deal signing polynomial via Liu channels |
| Signing budget/epoch | ~500 signatures | degree/2 before refresh |
| Introducers per channel | 3+ | Corrupt introducer protection |
| Liu key recycling | Continuous | Pool never depletes |

---

## 7. Open Questions

See [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md) for detailed analysis.

1. **Local trust verification** — validate personalized PageRank on real Liu channel graphs
2. **Bootstrap window hardening** — temporal diversity, network flooding, one-time PSK
3. **Optimal path selection** — internet topology-aware route diversity
4. **Epoch transition** — seamless re-dealing of signing polynomials
5. **Scale testing** — performance at 100, 1000, 10000 nodes
6. **Formal composition proof** — UC framework formalization. Current proof: [COMPOSITION_PROOF.md](COMPOSITION_PROOF.md) (20 theorems, concrete bounds, game-based composition)

---

## 8. Relationship to Liu Protocol

Liun treats `liuproto` as a black box with this interface:

```python
from liuproto.link import NetworkServerLink, NetworkClientLink
from liuproto.endpoint import Physics

# Given a PSK (from bootstrap or peer introduction):
client = NetworkClientLink(addr, physics, pre_shared_key=psk)
result = client.run_signbit_nopa(B=100000, n_runs=10)

# Result:
result['secure_bits']       # ITS key material (numpy uint8 array)
result['sigma_verified']    # sigma/p verification passed
result['psk_recycled']      # new PSK available for next batch
```

Liu provides:
- **ITS key expansion**: finite PSK -> unlimited key stream
- **ITS authentication**: polynomial MAC over M61
- **Continuous operation**: pool recycling, PSK never exhausts
- **Sigma verification**: channel quality monitoring

Liun provides:
- **Decentralized PSK establishment**: multi-path bootstrap + peer introduction
- **Threshold signatures**: Shamir DKG + USS
- **Network management**: overlay graph, membership, epoch rotation

Neither modifies the other. The interface is PSK in, ITS key bits out.
