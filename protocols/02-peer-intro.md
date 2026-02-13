# Protocol 02: Peer Introduction (ITS Overlay)

## Purpose

Enable any node to establish an ITS channel with any other node in the
network, using only existing ITS channels as transport. This makes the
network topology completely irrelevant for all operations after bootstrap.

## Prerequisites

- Node A has ITS channels with at least 3 nodes (from bootstrap or prior introductions)
- Target node C is reachable by at least 3 of A's existing contacts
- All ITS channels are Liu-backed (authenticated, encrypted, continuously renewable)

## Protocol

### Step 1: Introduction Request

A wants an ITS channel with C. A identifies m >= 3 mutual contacts
(nodes that have ITS channels with both A and C):

```
A <==ITS==> B1 <==ITS==> C
A <==ITS==> B2 <==ITS==> C
A <==ITS==> B3 <==ITS==> C
```

### Step 2: PSK Generation by Introducers

Each introducer Bi independently generates a random PSK component:

```
B1: generates PSK1 (random, 256 bits)
    sends PSK1 to A over ITS channel B1<->A
    sends PSK1 to C over ITS channel B1<->C

B2: generates PSK2 (random, 256 bits)
    sends PSK2 to A over ITS channel B2<->A
    sends PSK2 to C over ITS channel B2<->C

B3: generates PSK3 (random, 256 bits)
    sends PSK3 to A over ITS channel B3<->A
    sends PSK3 to C over ITS channel B3<->C
```

All transmissions occur over existing ITS channels. Eve observing TCP
sees only ITS-encrypted traffic — learns nothing.

### Step 3: PSK Combination

A and C independently combine the components:

```
PSK_AC = PSK1 XOR PSK2 XOR PSK3
```

Both compute the same value. This PSK is unknown to any individual
introducer (Bi knows PSKi but not the others).

### Step 4: PSK Expansion

If the combined PSK is shorter than Liu requires:

```
Full_PSK = expand(PSK_AC, target_length=32 + ceil(B/8))
```

Using a Toeplitz-based ITS extractor (same as in bootstrap).

### Step 5: Liu Channel Establishment

A and C run the Liu protocol over TCP using Full_PSK:

```python
# On C's side (server):
server = NetworkServerLink(addr, pre_shared_key=full_psk)
server.run_batch_signbit_nopa()

# On A's side (client):
client = NetworkClientLink(addr, physics, pre_shared_key=full_psk)
result = client.run_signbit_nopa(B=100000, n_runs=10)
```

Result: A and C now share an ITS channel with continuous key generation.

## Security Argument

**Corrupt introducer:** If B1 is controlled by Eve, Eve knows PSK1 but
not PSK2 or PSK3 (those traveled over ITS channels B2<->A and B2<->C,
which Eve cannot read). PSK_AC = PSK1 XOR PSK2 XOR PSK3 is
information-theoretically unknown to Eve because XOR with an unknown
uniform value (PSK2 or PSK3) is uniform.

**Threshold:** With m=3 introducers and honest majority (>=2 honest),
at least 2 PSK components are unknown to Eve. One unknown component
suffices for ITS secrecy of the XOR.

**Network topology:** Completely irrelevant. All PSK components travel
over ITS channels, not raw TCP. Eve's position in the network doesn't
matter.

**Composition:** Each peer introduction is independent. Compromise of
one introduction doesn't affect others.

## Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| m (introducers per channel) | 3 | Minimum. More = stronger against collusion |
| PSK component size | 256 bits | Sufficient for Liu PSK derivation |
| Introducer selection | Random from mutual contacts | Maximize independence |

## Overlay Graph Management

The overlay is the graph of ITS channels between nodes. Properties:

- **Self-healing:** If a channel expires or a node departs, reintroduce
  via alternative mutual contacts.
- **Growing:** Each new channel creates new mutual contacts for future
  introductions, accelerating growth.
- **Diameter:** With random introductions, the overlay graph has
  O(log N) diameter with high probability (random graph theory).

### Channel Lifecycle

```
1. Introduction (this protocol) --> PSK established
2. Liu key generation            --> Continuous ITS key stream
3. Key recycling                 --> Channel never expires
4. Node departure                --> Channel marked inactive
5. Re-introduction if needed     --> New PSK via new introducers
```

## Scaling

For a network of N nodes, each node needs O(log N) channels for
connectivity (random graph theory). Each channel requires one peer
introduction with m=3 introducers.

| N | Channels per node | Introductions per node |
|---|-------------------|----------------------|
| 100 | ~7 | ~7 |
| 1000 | ~10 | ~10 |
| 10000 | ~14 | ~14 |

Introductions are independent and can run in parallel.
