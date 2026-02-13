# Protocol 01: Multi-Path Bootstrap

## Purpose

Enable a new node to establish ITS shared secrets with existing network
members, without any prior relationship, over standard TCP/IP.

## Threat Model

- Eve passively observes some (but not all) network links
- Eve actively controls up to t < k/3 relay nodes
- Eve has unbounded computation

## Protocol

### Step 1: Node Discovery

New node A obtains a list of existing network nodes (addresses + node IDs).
This list is public — no secrecy needed. Obtained via:
- A well-known bootstrap endpoint (like DNS seeds in Bitcoin)
- Gossip from any reachable node
- Out-of-band (website, etc.)

### Step 2: Path-Diverse Contact

A selects k=20 target nodes B1...B20, maximizing geographic and
jurisdictional diversity:
- Different countries
- Different ISPs / autonomous systems
- Different continents where possible

### Step 3: Multi-Path Secret Sharing

For each target Bi, A establishes a shared secret:

```
A generates random value ri (256 bits)
A --> Bi: sends ri via TCP

Pairwise secret: K_ABi = ri
```

To protect against active adversaries on relay paths, use Shamir encoding:

```
A generates secret S (256 bits)
A encodes S into n=20 Shamir shares (threshold t=14)
A sends share_i to Bi via independent network route
Bi holds share_i

A and each honest Bi agree on S after threshold reconstruction.
(Corrupt Bi detected via consistency checking.)
```

### Step 4: Key Derivation

From the k shared secrets, A derives pairwise Liu PSKs:

```
For each honest Bi:
   PSK_ABi = expand(ri, target_length=32 + ceil(B/8))

   expand() is a deterministic ITS expansion:
   - Both A and Bi know ri
   - Use ri as seed for a Toeplitz-based extractor
   - Output: PSK of correct length for Liu protocol
```

### Security Argument

**Passive adversary:** Eve must observe ALL k routes to learn all ri values.
Missing even one ri means the corresponding pairwise key K_ABi is
information-theoretically unknown to Eve. With k=20 paths across diverse
infrastructure, Eve needs simultaneous presence on 20 independent routes.

**Active adversary:** Corrupt relay nodes can modify shares in transit.
Shamir threshold (k-of-n with k=14, n=20) detects and corrects up to
t=6 corrupted shares. Honest majority (>2/3) guarantees sufficient
honest shares for reconstruction.

**Composition:** Each pairwise key is independently ITS. Compromise of
one key does not affect others.

## Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| k (number of bootstrap targets) | 20 | Tunable per threat model |
| Share size | 256 bits | Single field element |
| Shamir threshold | 14 of 20 | 2/3 majority |
| Geographic diversity | >= 10 countries | Path independence |

## Transition

After bootstrap completes, A has pairwise secrets with up to 20 nodes.
These feed into Protocol 05 (Liu Integration) to establish full ITS channels.
Once ITS channels exist, Protocol 02 (Peer Introduction) takes over and
network topology becomes irrelevant.

## Bootstrap Options

The multi-path approach above is the default. Alternative bootstrap methods
for different threat environments:

**Temporal diversity:** Run Protocol 01 multiple times over days from
different network contexts. Each session adds ITS channels. Lower k per
session is acceptable.

**One-time PSK:** Physically exchange one 12.5 KB PSK with one existing
member. Bootstraps one Liu channel directly. Peer introduction handles
the rest.

**Computational bootstrap:** Single ECDH handshake (30 seconds) followed
by immediate Liu transition. Everlasting security — ITS after bootstrap.
