# Liun Implementation Roadmap

## Phase 1: Foundation (Proof of Concept)

**Goal:** Demonstrate the full ITS chain on a local testbed.

### 1.1 Shamir Secret Sharing over GF(M61)
- [ ] Implement Shamir split/reconstruct over GF(M61)
- [ ] Verify ITS privacy: k-1 shares reveal nothing
- [ ] Verify reconstruction: k shares recover exact secret
- [ ] Corrupted share detection via consistency checks
- **Why first:** Shamir is used by every other component (bootstrap,
  DKG, peer introduction). It's the most self-contained piece.

### 1.2 USS Signing and Verification
- [ ] Polynomial evaluation over GF(M61)
- [ ] Lagrange interpolation for threshold signing
- [ ] Verification via consistency check against held points
- [ ] Non-repudiation: dispute resolution with independent shares
- [ ] Signature budget tracking (count toward degree/2 limit)
- **Depends on:** 1.1 (Shamir for share distribution)

### 1.3 Liu Channel Wrapper
- [ ] Wrapper around liuproto's NetworkServerLink/NetworkClientLink
- [ ] Channel lifecycle: init, run batch, recycle PSK, resume
- [ ] Channel table management (active/idle/expired)
- [ ] Key material consumption API: request N ITS bits from channel
- **Depends on:** liuproto (existing, unchanged)

### 1.4 Local Integration Test
- [ ] 3-node local testbed (localhost, different ports)
- [ ] Manual PSK distribution (skip bootstrap for now)
- [ ] DKG among 3 nodes over Liu channels
- [ ] Threshold sign (2-of-3) and verify
- [ ] Verify: full chain is ITS (no computational primitives used)
- **Depends on:** 1.1, 1.2, 1.3

**Deliverable:** `python -m pytest` passes for local 3-node ITS signing.

---

## Phase 2: Overlay Network

**Goal:** Automate channel establishment and peer introduction.

### 2.1 Peer Introduction Protocol
- [ ] Introduction request/response message format
- [ ] Multi-introducer PSK generation (XOR of m contributions)
- [ ] PSK expansion to Liu size (Toeplitz extractor)
- [ ] Liu channel establishment from introduced PSK
- **Depends on:** Phase 1 (Liu channel wrapper)

### 2.2 Overlay Graph Manager
- [ ] Channel table with peer discovery
- [ ] Mutual contact identification (for introductions)
- [ ] Graph connectivity monitoring (maintain O(log N) channels)
- [ ] Channel health monitoring (Liu sigma verification)
- **Depends on:** 2.1

### 2.3 LAN Integration Test
- [ ] 10-node testbed on local network
- [ ] Bootstrap 3 nodes manually (PSK)
- [ ] Remaining 7 nodes join via peer introduction
- [ ] DKG among all 10 nodes
- [ ] Threshold signing (7-of-10) and verification
- **Depends on:** 2.1, 2.2, Phase 1

**Deliverable:** 10-node LAN testbed with automated peer introduction.

---

## Phase 3: Bootstrap

**Goal:** Enable strangers to join without prior PSK.

### 3.1 Multi-Path Bootstrap Protocol
- [ ] Node discovery (bootstrap node list)
- [ ] Geographic/AS diversity selection
- [ ] Multi-path secret transmission
- [ ] Shamir-encoded shares for active adversary protection
- [ ] Consistency verification and corrupt relay detection
- **Depends on:** Phase 1 (Shamir), Phase 2 (overlay)

### 3.2 Temporal Diversity Mode
- [ ] Multi-session bootstrap across different network contexts
- [ ] Session state persistence (resume bootstrap over days)
- [ ] Channel accumulation and overlay transition
- **Depends on:** 3.1

### 3.3 One-Time PSK Bootstrap
- [ ] QR code / file-based PSK exchange
- [ ] Single-channel bootstrap -> peer introduction expansion
- [ ] Minimal viable bootstrap: one meeting, full participation
- **Depends on:** Phase 2 (peer introduction)

### 3.4 WAN Integration Test
- [ ] 5+ nodes across different networks (VPS providers, home, etc.)
- [ ] At least one node bootstraps without prior PSK (multi-path)
- [ ] Full protocol chain: bootstrap -> overlay -> DKG -> signing
- **Depends on:** 3.1, 3.2 or 3.3

**Deliverable:** Stranger can join network and participate in ITS signing.

---

## Phase 4: Epoch Management

**Goal:** Sustainable long-term operation.

### 4.1 Signing Polynomial Rotation
- [ ] Epoch boundary protocol (agreed rotation schedule)
- [ ] Overlapping validity (old polynomial valid during grace period)
- [ ] Fresh DKG with Liu-generated randomness
- [ ] Seamless cutover with no signing gap

### 4.2 Membership Dynamics
- [ ] Node join mid-epoch (receive current polynomial shares)
- [ ] Node departure (shares invalidated, threshold maintained)
- [ ] Threshold adjustment as network size changes

### 4.3 Long-Running Test
- [ ] 10-node testbed running for 24+ hours
- [ ] Multiple epoch rotations
- [ ] Node join/leave events
- [ ] Continuous signing throughout

**Deliverable:** Sustained 24-hour operation with epoch rotations.

---

## Phase 5: Hardening

**Goal:** Adversarial resilience.

### 5.1 Byzantine Fault Testing
- [ ] Inject corrupt nodes (send wrong shares, wrong signatures)
- [ ] Verify detection and exclusion
- [ ] Measure: time to detect, false positive rate

### 5.2 Network Adversary Testing
- [ ] Simulate partial network observation
- [ ] Simulate BGP-style route manipulation
- [ ] Simulate eclipse (single-ISP bottleneck)
- [ ] Measure: what fraction of surveillance breaks bootstrap?

### 5.3 Sybil Resistance (Research)
- [ ] Prototype social graph / sponsorship mechanism
- [ ] Rate-limited membership growth
- [ ] Evaluate: cost to create Sybil identities

**Deliverable:** Quantified resilience against modeled adversaries.

---

## Phase 6: Scale

**Goal:** Demonstrate at realistic network sizes.

### 6.1 100-Node Testbed
- [ ] Deploy across multiple cloud providers / regions
- [ ] Full protocol: bootstrap, overlay, DKG, signing, epoch rotation
- [ ] Measure: DKG latency, signing throughput, key generation rate

### 6.2 1000-Node Simulation
- [ ] Simulated network (overlay only, mock Liu channels)
- [ ] Measure: overlay diameter, DKG communication cost, scaling behavior
- [ ] Identify bottlenecks

### 6.3 Performance Optimization
- [ ] Parallel Liu channels (multiple concurrent key generation streams)
- [ ] Batched DKG (reduce round trips)
- [ ] Optimized polynomial evaluation (NTT over M61?)

**Deliverable:** Performance data at 100 real nodes, 1000 simulated.

---

## Development Priorities

```
CRITICAL PATH:

  Phase 1.1 (Shamir) ──> Phase 1.2 (USS) ──> Phase 1.4 (local test)
                                                     |
  Phase 1.3 (Liu wrapper) ─────────────────────────-─┘
                                                     |
                                                     v
                                              Phase 2 (overlay)
                                                     |
                                                     v
                                              Phase 3 (bootstrap)
                                                     |
                                                     v
                                              Phase 4 (epochs)
                                                     |
                                                     v
                                              Phase 5 (hardening)
                                                     |
                                                     v
                                              Phase 6 (scale)
```

Phase 1 is the foundation. Everything else builds on it. Start there.
