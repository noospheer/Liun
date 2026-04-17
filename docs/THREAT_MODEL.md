# Threat model

The honest "before you trust this, here's what you're actually getting"
document. Read before deploying.

Liun-node is a research implementation of an information-theoretically
secure (ITS) key-agreement + messaging protocol. This document describes
the explicit adversary model, what is and isn't in scope, and the
residual risks that *no* cryptographic system could eliminate.

---

## 1. What the system is trying to protect

For each of the three deployed applications:

### 1.1 `chat`
- **Confidentiality** of the message plaintext between the two peers.
- **Integrity** / authenticity of each message — a peer or MITM cannot
  forge or alter messages without detection.
- **Forward secrecy** — an attacker who compromises a peer's machine
  *after* the session cannot decrypt messages exchanged earlier in the
  session.

Explicitly **not** protected by `chat`:
- The *existence* of the session — anyone with packet visibility learns
  that two IPs are exchanging ciphertext at certain times (metadata).
- The *endpoints* — source IP, destination IP, and port are visible.
- The *timing / size* — traffic analysis can distinguish chat messages
  from Liu exchange rounds by size, and by the visible temporal pattern
  of messages.

### 1.2 `liun-node` (network peer daemon)
- **Discovery** of other nodes by their 384-bit ID, via the Kademlia
  DHT. The DHT layer makes no authenticity claim on its own (see §2.2);
  it's a hint layer.
- **Persistent peer cache** so seed lists become optional after first
  contact.
- **Session TCP listener** for incoming Liun channels from discovered
  peers. Channels themselves get full chat-like protection once
  established.

### 1.3 `relay`
- Dead-drop storage for bootstrap shares (k-path XOR).
- No authentication on individual shares; security comes from the k-way
  XOR structure.

---

## 2. Adversary models we consider

### 2.1 Adversary A (default deployment)

**Capability**:
- Full visibility into all internet-scale traffic along paths they
  happen to control (not universal). Can observe, drop, reorder, inject
  packets.
- Unbounded computational power — `assume all computational crypto is
  breakable` is the Liun premise. No reliance on ECDSA, RSA, DH, TLS,
  or any computational hardness assumption for the core protocol.
- May run their own DHT nodes, their own relays, their own Liun peers.
- May attempt to coerce or compromise service providers (ISPs, VPS
  operators, DNS) within their reach.
- Cannot physically touch the user's hardware or memory.
- Does **not** have universal observation — at least ONE of the k
  bootstrap relays operates in infrastructure beyond their reach.

**Claim**:
- **Chat messages remain confidential and unforgeable** against this
  adversary, conditional on an ITS RNG source (`--rng auto` detects
  RDSEED, RNDR, or trandom).
- **Bootstrap PSK remains secret** given the "≥1 unobserved relay"
  assumption.
- **Channel handshakes with wrong peers fail** (MAC verification
  catches mismatched PSKs).

**Non-claim**:
- Traffic-analysis resistance — we make none.
- Availability against DoS — rate-limiting mitigates but doesn't
  eliminate.

### 2.2 Adversary B (DHT-only)

**Capability**: same as A plus the ability to poison DHT entries.

**Claim**:
- Poisoning the DHT at most degrades discoverability, never breaks
  confidentiality or authenticity. The DHT is an unauthenticated hints
  layer; any address it returns is validated by the Liun handshake
  before any secret material is exchanged. A bad hint causes the
  handshake to fail, not a silent connection to the attacker.

### 2.3 Adversary C (global passive wire adversary)

**Capability**: observes every packet on every transit path on the
entire internet (NSA-on-steroids). Has taps on every relay operator.

**Claim**: none. *No* cryptographic system achieves ITS from zero
prior trust against a truly universal observer — this is an
information-theoretic fact, not a Liun limitation.

**Mitigation**: pre-shared PSK via an out-of-band channel (in-person,
USB stick, trusted courier). The chat can then run over this PSK
directly, bypassing the multi-path bootstrap's route-diversity
assumption. This is the QKD-equivalent mode.

### 2.4 Adversary D (local, same machine)

**Capability**: runs code as the same user or with root on one of the
peer machines.

**Claim**:
- Against a **future** compromise (attacker arrives after the session):
  forward secrecy holds. Pool state lives only in RAM, zeroized on
  drop. Process death wipes all key material. No persistence to disk
  (we explicitly do not persist pools, see `docs/SECURITY.md`).
- Against a **concurrent** same-user attacker: we make no claim. If
  the attacker can read the process's memory (ptrace, /proc/mem,
  same-uid access), they have everything.
- Against a **concurrent** root attacker: no claim. Root can read any
  process memory.

**Mitigations that help but don't close this**:
- `prctl(PR_SET_DUMPABLE, 0)` denies same-uid ptrace (root can still
  override).
- The systemd unit runs as a dedicated `liun` user with `NoNewPrivileges`
  and sandbox restrictions.

### 2.5 Adversary E (physical / cold-boot)

**Capability**: physical access to the machine's RAM or storage, e.g.
via cold-boot attack (freeze RAM, read afterward) or a stolen laptop.

**Claim**: limited.
- `MemorySwapMax=0` (systemd) + `mlockall` ensures key material never
  hits disk — stolen-laptop-from-powered-off-state leaks nothing.
- Cold-boot attack with live RAM access: not mitigated at the
  software level. Hardware-level memory encryption (Intel SGX, AMD
  SEV) would help; we don't use them.

### 2.6 Adversary F (supply chain)

**Capability**: compromises a crate on crates.io, or injects malicious
code during the build.

**Claim**: limited.
- `cargo audit` (RustSec advisories) + `cargo deny` (license / source /
  duplicate policy) are in CI and flag known issues.
- Reproducible builds (`cargo build --locked`) verify the binary
  matches source.
- Running-from-source is always possible; trusted binary distribution
  is a social/build-infrastructure question we don't solve alone.

### 2.7 Adversary G (quantum-equipped, future)

**Capability**: has a large-scale quantum computer, can break RSA /
ECDSA / ECDH / discrete log in polynomial time.

**Claim**:
- This is the adversary Liun was explicitly designed for. The *running*
  protocol makes no computational-hardness assumption (given TRNG). A
  quantum adversary gains nothing over a classical one against chat
  traffic, Liu refresh exchanges, or OTP/MAC primitives.
- **Caveat**: Liun's boostrap / binary distribution / seed list
  discovery currently rely on classical internet infrastructure (HTTP,
  TCP, DNS) which has computational underpinnings. None of those carry
  *keys*, but a quantum adversary who owned the web / DNS could
  substitute fake seed lists or bad binaries — the usual computational
  attacks. Real-world Liun deployment needs out-of-band verification of
  the binary (fingerprint comparison via multiple independent channels,
  reproducible builds, etc).

---

## 3. Known residual risks

Things we **don't** currently mitigate and are honest about:

- **Traffic analysis.** Metadata (when, how much, to whom) leaks. A
  Tor-equivalent transport layer would help; not built in.
- **Side channels beyond timing.** Cache attacks, Spectre-class
  transient-execution leaks, power analysis, EM emissions. Not
  addressed. Constant-time discipline at source level helps against
  naive timing only.
- **Active denial of service.** Rate-limiting at the DHT is a mitigation,
  not a solution. A well-resourced attacker can exhaust a single node's
  network or compute.
- **Eclipse attacks.** A new node joining via a malicious seed can be
  isolated from the real network. Mitigation is multi-path bootstrap
  (k ≥ 20 diverse relays); the code supports this but requires actual
  deployment of ≥ 20 diverse relays by different operators.
- **Cold-boot against live process memory.** Out of scope.
- **Human error.** Sharing a session-id with the wrong person, typing
  chat into the wrong window, etc. We do nothing to protect against
  this.
- **Funding-layer attribution.** The public-goods pool (see
  [FUNDING.md](FUNDING.md)) routes ETH to nodes based on a
  deterministic tally that any node can re-run and challenge. Defences
  are: (1) per-pair ITS MACs on every claim, (2) required positive
  trust on BOTH parties of every credited session, (3) a 7-day
  on-chain challenge window with slashable publisher deposit. The
  remaining risk is the seed set of the public trust graph — if every
  seed (EF, Signal, community groups) colluded, they could inject
  trusted Sybils. This **does not** compromise user chat:
  confidentiality and authenticity of protocol traffic are independent
  of the funding layer and remain ITS-secure regardless of who got
  paid what.

---

## 4. Things that can only be checked, not proved

- **The RNG is actually a TRNG.** Four backends are supported:
  Intel RDSEED (thermal noise, SP 800-90C health tests), ARM RNDR
  (equivalent), trandom (multi-source software extraction via LHL),
  or urandom (CSPRNG fallback, NOT ITS). The ITS claim requires one
  of the first three. If the chosen TRNG's output isn't genuinely
  random (e.g. Intel backdoor, or trandom's noise sources are all
  predictable), the ITS chain degrades to the actual output quality.
- **The Rust compiler emits what we think it emits.** Branchless source
  code doesn't guarantee branchless machine code; rustc's optimizer may
  introduce or elide branches. Independent compiler verification
  (bolero, cargo-asm for review) is a next step.
- **The Lean proofs cover what we think they cover.** The Lean proofs
  are machine-checked for the algorithms we define in Lean. The
  correspondence between "algorithm in Lean" and "algorithm in Rust" is
  manual; Kani / Creusot could make it mechanical.
- **The supply chain.** Transitive crate authors are humans with
  repositories. We audit, but audits catch known issues, not future
  compromise.

---

## 5. Deployment posture checklist

Before you run `liun-node` in production against a real adversary,
verify the following — anything **not** ticked drops your effective
security to a weaker tier:

- [ ] Running with an ITS RNG source (`--rng auto` picks the best).
      Options: RDSEED (Intel), RNDR (ARM), trandom (any x86 VM).
      Without one of these, you have CSPRNG-strength, not ITS.
      Cloud VMs: install trandom (`sudo ./scripts/install-trandom.sh`).
- [ ] Systemd unit with hardening (`deploy/liun-node.service`) OR
      equivalent sandboxing.
- [ ] `MemorySwapMax=0` in the unit, OR `swapoff -a` on the host, so
      key material never touches disk.
- [ ] `--mlock-memory` with `CAP_IPC_LOCK` available.
- [ ] Core dumps disabled (the default; not overridden by
      `--debug-allow-core-dumps`).
- [ ] Bootstrap relays operated by **diverse** entities on **diverse**
      infrastructure. `k = 3` on a single cloud = `k = 1` against that
      cloud.
- [ ] Seed list and binary verified through ≥ 2 independent channels.
- [ ] Threat model understood — you're protecting chat content against
      computationally-unbounded adversaries, not metadata against
      traffic analysts.

---

## 6. Reporting a security issue

Open a private GitHub security advisory, or email the maintainer
(when there is one publicly designated). Do not open a public issue.

Publishing a security claim about Liun that extends beyond this
document is an error and should be corrected.
