# Protocol 04: USS Threshold Signing

## Purpose

Produce digital signatures that are:
- **ITS unforgeable**: no computational power can forge
- **Threshold**: k-of-n nodes collaborate to sign
- **Verifiable**: any node with verification shares can check
- **Non-repudiable**: signer cannot deny having signed

## Prerequisites

- Shamir DKG has completed (Protocol 03)
- Each node holds: one signing share + verification shares
- All communication over ITS channels

## Background: USS over GF(M61)

The signing key is a polynomial F(x) of degree d over GF(M61).
A signature on message m is sigma = F(m). Verification checks
sigma against independently held evaluation points of F.

The Liu protocol already uses polynomial evaluation over GF(M61)
for its Wegman-Carter MAC. USS extends this from symmetric (both
parties know F) to asymmetric (signer knows F, verifier knows
partial evaluations).

## Protocol

### Signing

To sign message m, the signing committee (k nodes) collaborates:

```
1. Each committee member i holds share si = F(i)
2. Each member computes partial signature:
       sigma_i = si * Li(m)  mod M61
   where Li(m) is the Lagrange basis polynomial for point i
   evaluated at m.

3. Combiner (any node) collects k partial signatures and sums:
       sigma = sum(sigma_i for i in committee)  mod M61

4. Broadcast (m, sigma)
```

The Lagrange interpolation ensures sigma = F(m) without any single
node knowing F.

### Verification

Each verifier j holds verification shares: a set of points
{(v_j1, F(v_j1)), (v_j2, F(v_j2)), ...} — enough for consistency
checking but not enough to reconstruct F.

```
Verifier j checks:
    Does sigma = F(m) interpolate consistently with my known points?

Specifically:
    Given my d/2 known evaluations of F, and the claimed (m, sigma),
    check that these d/2 + 1 points lie on a polynomial of degree d.

    This is a polynomial consistency check — linear algebra over GF(M61).
```

### Non-Repudiation (Dispute Resolution)

If node X claims "committee signed message m" and node Y disputes:

```
1. X presents (m, sigma) and their verification check result
2. Y independently checks (m, sigma) against their OWN verification shares
3. Y's shares are DIFFERENT from X's (distributed independently in DKG)
4. If both X and Y's checks pass --> signature is valid
5. If X passes but Y fails --> X may be lying (forged sigma)
6. Majority vote among all verifiers resolves disputes

Key property: A forger controlling X would need to produce sigma that
passes ALL verifiers' independent checks. This requires knowing enough
of F to reconstruct it — which requires t shares (ITS impossibility
with fewer).
```

## Security Argument

**ITS unforgeability:** Forging a signature on message m requires
computing F(m). Reconstructing F requires t evaluation points.
Each verifier holds d/2 < t points. Even an adversary controlling
up to t-1 nodes (with their shares) cannot reconstruct F. This
is an information-theoretic impossibility — not a computational one.

**Threshold signing:** The Lagrange interpolation in the signing
protocol is a standard technique. k shares suffice to evaluate F
at any point. k-1 shares reveal nothing about F(0) or F(m) for
new m.

**Independent verification:** Different verifiers hold different
evaluation points. A forgery must be consistent with ALL verifiers'
points simultaneously. This is equivalent to reconstructing F,
which requires >= t points.

**Non-repudiation:** Since verification shares are independent
and distributed over ITS channels, no single party can forge
a signature that passes another party's check. The majority
adjudication is ITS — computational power doesn't help the forger.

## Signature Budget

Each signature reveals one evaluation point (m, F(m)) publicly.
After ~d/2 signatures, enough public points exist for anyone to
reconstruct F (threshold of d+1 points).

```
Signatures per epoch: ~d/2

For d=1000: ~500 signatures per epoch
For d=10000: ~5000 signatures per epoch
```

Epoch rotation (Protocol 03 re-deal) refreshes the polynomial using
fresh Liu key material. No gap in signing capability.

## Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| Field | GF(M61) | 2^61 - 1, same as Liu MAC |
| Polynomial degree d | 1000 | Adjustable per signing rate |
| Signing threshold k | 2N/3 + 1 | Honest majority |
| Verification points per node | d/2 | Enough to verify, not to forge |
| Signature size | 1 field element (8 bytes) + message | Compact |
| Epoch (re-deal interval) | ~1 hour or ~d/2 signatures | Whichever comes first |

## Message Encoding

Messages are encoded as field elements in GF(M61) for polynomial
evaluation. For messages longer than 61 bits:

```
1. Split message into 60-bit chunks: m1, m2, ..., mk
2. Sign each chunk: sigma_i = F(m_i)
3. Full signature: (sigma_1, sigma_2, ..., sigma_k)
```

Or use a Merkle tree:
```
1. Build Merkle tree of message chunks
2. Sign the root hash (truncated to 60 bits)
3. Signature = F(root) + Merkle tree
```

Note: Merkle tree root is a hash — computational. For full ITS,
use the chunk method. The trade-off is signature size.

## Algebraic Compatibility with Liu

The Liu protocol uses polynomial MAC over GF(M61):

```
Liu MAC:  tag = f(r) + s  mod M61
USS sign: sigma = F(m)    mod M61
```

Same field, same polynomial evaluation, same arithmetic. The
algebraic infrastructure is shared. This is not a coincidence —
USS naturally extends the Liu MAC from symmetric to asymmetric.
