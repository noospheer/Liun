# Protocol 03: Shamir Distributed Key Generation

## Purpose

Collectively generate a threshold signing polynomial such that:
- No single node ever sees the full polynomial
- Any k nodes can collaboratively sign
- Any k-1 nodes learn zero information about the signing key
- No trusted dealer required

## Prerequisites

- All participating nodes have pairwise ITS channels (from Protocols 01/02)
- Honest majority: > 2/3 of N nodes are honest

## Background: Shamir Secret Sharing

A secret s is encoded as a random polynomial f(x) of degree t-1 over
a finite field F, where f(0) = s. Each party i receives share f(i).
Any t shares reconstruct f (and thus s) via Lagrange interpolation.
Any t-1 shares reveal zero information about s (information-theoretic).

## Protocol: Feldman-style DKG (ITS variant)

Standard Feldman DKG uses computational commitments (Pedersen/discrete-log).
We replace these with ITS commitments via pairwise MACs.

### Step 1: Individual Polynomial Generation

Each node i generates a random polynomial fi(x) of degree t-1 over GF(M61):

```
fi(x) = ai0 + ai1*x + ai2*x^2 + ... + ai(t-1)*x^(t-1)  mod M61

where M61 = 2^61 - 1 (Mersenne prime, same as Liu's MAC field)
```

The coefficients ai0, ai1, ..., ai(t-1) are generated from node i's
local randomness (private, never transmitted in the clear).

### Step 2: Share Distribution

Node i computes fi(j) for every other node j and sends it over the
ITS channel i<->j:

```
For each node j != i:
    share_ij = fi(j) mod M61
    Send share_ij to node j over ITS channel i<->j
```

ITS channel guarantees: Eve cannot read the share (confidentiality)
and cannot modify it (authentication via Liu MAC).

### Step 3: ITS Consistency Verification

In standard Feldman DKG, consistency is checked via Pedersen commitments
(computational). For ITS, we use pairwise verification:

```
For each pair (i, j):
    Node i sends MAC(share_ij) to a random subset of other nodes
    Those nodes verify by asking node j to confirm receipt
    Inconsistency detected --> node i marked as corrupt
```

With honest majority, corrupt nodes are identified and excluded.

### Step 4: Share Combination

Each node j computes its share of the combined polynomial:

```
sj = sum over all non-excluded nodes i: fi(j)  mod M61
```

The combined polynomial F(x) = sum of all fi(x) is random
(because honest nodes contributed truly random polynomials)
and has degree t-1.

**Key property:** No single node knows F(x). Each node j knows only
its own share sj = F(j). The signing key F(0) is never computed
by anyone.

### Step 5: Verification Share Generation

For USS verification, each node also needs verification points.
These are additional evaluations of F at public points:

```
Signing points:     F(1), F(2), ..., F(N)     (one per node, private)
Verification points: F(v1), F(v2), ..., F(vm)  (per-verifier sets, private)
```

The verification points are chosen so that each verifier has enough
to verify (consistency check) but not enough to reconstruct F
(which requires t points total).

## Security Argument

**ITS confidentiality:** All share transmissions occur over ITS channels.
Eve learns nothing about any fi(j) regardless of computational power.

**ITS integrity:** Liu MAC authentication on each channel prevents share
modification. Corrupt nodes can only contribute incorrect shares from
their own polynomial (detectable via consistency verification).

**No trusted dealer:** The combined polynomial F(x) is the sum of all
individual contributions. No single party chose it. As long as at least
one honest node contributed a truly random polynomial, F(x) is random.

**Threshold security:** Any t-1 shares of a degree-(t-1) polynomial
reveal zero information about F(0). This is unconditional (Shamir's
original proof).

## Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| Field | GF(M61) | Same field as Liu MAC — compatible algebra |
| Threshold t | 2N/3 + 1 | Honest majority |
| Polynomial degree | t - 1 | Standard Shamir |
| Shares per node | 1 signing + m verification | USS requirement |

## Epoch Rotation

Signing polynomials have bounded use (~degree/2 signatures). At each
epoch boundary:

1. Run DKG again with fresh randomness from Liu channels
2. Old polynomial remains valid during grace period
3. Cutover at agreed epoch boundary
4. Liu's continuous key generation ensures fresh randomness is always available

## Communication Cost

| Phase | Messages | Per-message size | Total (N=100, t=67) |
|-------|----------|-----------------|---------------------|
| Share distribution | N*(N-1) | 1 field element (8 bytes) | ~80 KB |
| Consistency check | O(N^2) | MAC tag (8 bytes) | ~80 KB |
| Total per DKG | O(N^2) | | ~160 KB |

For N=100, this completes in seconds over Liu channels generating
Mbps of key material.
