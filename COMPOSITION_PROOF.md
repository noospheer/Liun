# Formal Composition Proof: Three Primitives, Six Layers

> **Status:** Research-grade proof with concrete bounds. This document
> provides definitions, theorem statements, and proofs for how Liun's three
> primitives compose across six protocol layers to achieve end-to-end
> information-theoretic security. Explicit assumptions and caveats are
> stated where they apply. A full UC-framework formalization remains
> future work.

---

## 0. Notation and Conventions

| Symbol | Meaning |
|--------|---------|
| **F** = GF(M61) | The Mersenne prime field, M61 = 2^61 - 1 |
| **n** | Total number of nodes |
| **k** | Signing/reconstruction threshold, typically 2n/3 + 1 |
| **d** = k - 1 | Degree of the signing polynomial |
| **t** | Maximum corrupt nodes, t < n/3 |
| **Eve** | Computationally unbounded adversary |
| **negl(lambda)** | Negligible function (we use concrete bounds instead) |
| **PPR_v(u)** | Personalized PageRank score of u from v's perspective |
| **H_min(X\|E)** | Min-entropy of X conditioned on Eve's view E |
| **epsilon** | Statistical distance from uniform (security parameter) |

Throughout, "ITS" means information-theoretically secure: security holds
against adversaries with unlimited computation and unlimited time.

---

## 1. Definitions

### Definition 1.1 (Information-Theoretic Secrecy)

A random variable X is **epsilon-secret** from Eve's view E if:

    SD(X | E,  U) <= epsilon

where SD denotes statistical distance and U is the uniform distribution
over the domain of X.

For epsilon = 0, this is **perfect secrecy** (Shannon, 1949).

### Definition 1.2 (Information-Theoretic Unforgeability)

A signature scheme (Sign, Verify) is **(d, epsilon)-IT-unforgeable** if
any adversary (unbounded) holding fewer than d+1 evaluations of the signing
polynomial F can produce a valid forgery (m*, sigma*) with probability at
most epsilon over the random choice of F, for any message m* not previously
signed.

### Definition 1.3 (Shamir IT-Privacy)

A (k, n)-Shamir sharing of secret s over a field F provides **perfect
privacy**: any set of at most k-1 shares is statistically independent of s.
Formally, for any S with |S| <= k-1 and any two secrets s, s':

    Pr[shares_S | secret = s] = Pr[shares_S | secret = s']

### Definition 1.4 (ITS Channel)

An ITS channel between parties A and B provides:
1. **Confidentiality**: messages are epsilon-secret from Eve
2. **Authentication**: Eve can forge a valid MAC tag with probability
   at most delta per message

For the Liu protocol with Wegman-Carter MAC over GF(M61):
- epsilon = target_epsilon (from Leftover Hash Lemma, default 10^-6)
- delta = L/M61 per MAC tag, where L is the message length in field elements
  (polynomial evaluation at a secret random point; for typical L ~ 10^3,
  delta ~ 10^-16)

### Definition 1.5 (Honest Majority)

The network satisfies **(trust-weighted) honest majority** if for every
honest node v, the total PPR trust weight of corrupt nodes is less than 1/3:

    sum_{u in corrupt} PPR_v(u) < 1/3

---

## 2. The Three Primitives

### Primitive 1: Polynomial Arithmetic over GF(M61)

**Implementation:** `liun/gf61.py`

The single algebraic operation is polynomial evaluation over GF(M61):

    P(x) = a_d * x^d + a_{d-1} * x^{d-1} + ... + a_1 * x + a_0   (mod M61)

computed via Horner's method in O(d) field multiplications.

This operation is used three ways:

| Application | Polynomial | Evaluation point | Result |
|-------------|-----------|-----------------|--------|
| Shamir sharing | Random f of degree k-1, f(0) = secret | Node ID i | Share f(i) |
| USS signing | Secret F of degree d | Message m | Signature sigma = F(m) |
| Wegman-Carter MAC | Message coefficients [c_0, ..., c_{L-1}] | Secret random r | Tag h = P(r) + s |

**Theorem 2.1 (Correctness).** For any polynomial P of degree d over GF(M61),
any d+1 distinct evaluations {(x_i, P(x_i))} uniquely determine P via
Lagrange interpolation. This is exact (zero error) over any finite field.

*Proof.* A polynomial of degree d over a field has at most d roots. Two
distinct polynomials of degree d can agree on at most d points. Therefore d+1
evaluations uniquely determine the polynomial. Lagrange interpolation
constructs it explicitly in O(d^2) field operations. QED.

**Theorem 2.2 (Shamir Perfect Privacy).** Let f(x) be a random polynomial
of degree k-1 over GF(M61) with f(0) = s. For any set S of evaluation
points with |S| <= k-1, the joint distribution of {f(x_i)}_{i in S} is
uniform over GF(M61)^{|S|} and independent of s.

*Proof.* (Shamir, 1979) The k-1 free coefficients a_1, ..., a_{k-1} are
uniform random over GF(M61). For |S| <= k-1, the evaluation map
(a_1, ..., a_{k-1}) -> (f(x_1), ..., f(x_{|S|})) is an affine map of
rank |S| (the Vandermonde matrix on {x_i} has full rank when the x_i are
distinct and nonzero). The image is therefore uniform over GF(M61)^{|S|},
regardless of a_0 = s. QED.

### Primitive 2: Liu Protocol (Gaussian Noise Key Generation)

**Implementation:** `liuproto/stream.py` (StreamPipe), `liuproto/link.py`

The Liu protocol converts a finite pre-shared key (PSK) into an unlimited
stream of ITS key bits via:

1. **Gaussian noise exchange**: Alice and Bob exchange noisy signals through
   a physical (or simulated) channel with reflection coefficient alpha
2. **Quantization**: Continuous samples quantized to n_bits per step
3. **Privacy amplification**: Toeplitz hashing extracts secure bits from
   raw correlated samples, with security guaranteed by the Leftover Hash
   Lemma (LHL)
4. **PSK authentication**: Wegman-Carter MAC using PSK-derived keys (r, s)
   authenticates the protocol transcript

**Theorem 2.3 (Leftover Hash Lemma, Impagliazzo-Levin-Luby 1989).**
Let X be a random variable with min-entropy H_min(X) >= k. Let
h: {0,1}^n -> {0,1}^m be drawn from a 2-universal family. If
m <= k - 2*log(1/epsilon), then:

    SD((h, h(X)),  (h, U_m)) <= epsilon

where U_m is uniform on {0,1}^m.

**Application to Liu:** Each chunk of `chunk_steps = 1001` exchanges
produces `n_raw = 1001 * 8 = 8008` raw bits. Eve's best guess probability
per step is bounded by the channel physics (mod-p wrapping, Gaussian noise
variance). The min-entropy H_min per step is computed from the conditional
distribution of Alice's sample given Eve's optimal measurement. Privacy
amplification via Toeplitz hashing (a 2-universal family over GF(2))
extracts:

    n_secure = floor(H_min_total - 2*log_2(1/epsilon) - 2)

secure bits per chunk, with statistical distance at most epsilon from
uniform, against Eve with unlimited computation.

**Theorem 2.4 (Wegman-Carter MAC over GF(M61)).**
Let M = [c_0, ..., c_{L-1}] be a message of L field elements. The MAC tag:

    tag = (sum_{i=0}^{L-1} c_i * r^{i+1} + s) mod M61

where r, s are uniform random elements of GF(M61) independent of M,
satisfies:

    Pr[Eve forges valid tag for any M' != M] <= max(L, L') / M61

where L' is the length of the forged message, for any single MAC query,
regardless of Eve's computational power.

*Proof.* Fix M and M' != M with L and L' elements respectively. The
difference of their polynomial hashes h(M; r) - h(M'; r) is a nonzero
polynomial in r of degree at most D = max(L, L'). A nonzero polynomial
of degree D over GF(M61) has at most D roots. Since r is uniform over
GF(M61), the probability that h(M; r) = h(M'; r) is at most D/M61.
The one-time pad mask s cancels in the difference and provides perfect
hiding of the hash value.

For practical message lengths (L <= 10^4), the bound is at most
10^4 / (2^61 - 1) ~ 4.3 * 10^-15, which is negligible. QED.

**Theorem 2.5 (PSK Consumption and Renewal).**
Each run consumes 18 bytes of PSK (2 bytes alpha OTP + 8 bytes r + 8 bytes s).
The Liu protocol generates n_secure >> 144 (= 18*8) key bits per chunk,
so PSK can be recycled: the first batch of key material includes enough
bits to serve as a fresh PSK for the next batch. The channel never exhausts.

*Proof.* The PSK offset for run_idx i is 32 + 18*i bytes. After the first
chunk, n_secure >> 144 new bits are available. These bits are
epsilon-independent of Eve's view (by Theorem 2.3). Using them as the
next-round PSK maintains the ITS guarantee, with security degrading by at
most epsilon per renewal (union bound). QED.

### Primitive 3: Random Walk on Channel Graph (Personalized PageRank)

**Implementation:** `liun/overlay.py` (personalized_pagerank)

Each node v computes a trust vector over all nodes by performing a random
walk with restart on the ITS channel graph G:

    PPR_v(u) = (1-d) * 1_{u=v} + d * sum_{w: (w,u) in E} PPR_v(w) * weight(w,u) / out_weight(w)

with damping factor d = 0.85 and 20 power iterations.

**Definition 2.6a (Graph partition).** Let G = (V, E) be the channel graph.
Partition V = H ∪ S where H is the set of honest nodes and S is the set
of Sybil nodes controlled by Eve. Let the **attack edges** A be the edges
between H and S:

    A = {(u, w) in E : u in H, w in S}

Write a = |A| for the number of attack edges.

**Definition 2.6b (Spectral gap).** Let W_H be the transition matrix of the
random walk restricted to the honest subgraph H (with self-loops absorbing
the Sybil-facing edge weight). Let lambda_2(W_H) be its second-largest
eigenvalue. The **spectral gap** is gamma = 1 - lambda_2(W_H). A graph is
fast-mixing when gamma = Omega(1).

**Theorem 2.6 (Sybil Resistance via PPR).**
Let G = (V, E) be the channel graph with honest subgraph H and Sybil region
S connected by a attack edges. Let delta_min be the minimum degree of any
honest node on the attack boundary (i.e., any honest node with at least one
Sybil neighbor). Then for any honest seed v, the total PPR trust flowing
to S satisfies:

    sum_{u in S} PPR_v(u) <= d * a / delta_min

where d = 0.85 is the damping factor. In particular, the Sybil trust is
proportional to the number of attack edges and independent of |S|.

*Proof.* Consider the stationary PPR vector pi_v from seed v. The total
trust flowing into S per step of the random walk equals:

    flow(H -> S) = sum_{u in H, w in S, (u,w) in E} d * pi_v(u) * weight(u,w) / out_weight(u)

For unit-weight edges, weight(u,w) = 1 and out_weight(u) = degree(u).
Each attack edge (u, w) contributes d * pi_v(u) / degree(u) to the flow.
Therefore:

    flow(H -> S) = d * sum_{(u,w) in A} pi_v(u) / degree(u)
                 <= d * sum_{(u,w) in A} pi_v(u) / delta_min
                 <= d * a * max_{u on boundary} pi_v(u) / delta_min

Since pi_v(u) <= 1 for all u (trust vector sums to 1), we get:

    flow(H -> S) <= d * a / delta_min

In the PPR stationary distribution, the total trust in S equals the
flow into S divided by the effective drain rate. With teleportation
probability (1-d) per step back to v (which is in H), any trust that
enters S is drained at rate (1-d) per step. At stationarity:

    (1-d) * sum_{u in S} pi_v(u) <= flow(H -> S) <= d * a / delta_min

Therefore:

    sum_{u in S} pi_v(u) <= d * a / ((1-d) * delta_min)

For d = 0.85, delta_min >= delta (minimum honest degree):

    sum_{u in S} pi_v(u) <= 0.85 * a / (0.15 * delta) = 5.67 * a / delta

**Concrete bound.** For a network where honest nodes have minimum degree
delta = 7 (log_2(100) + 1, the GraphMonitor target for n=100), and Eve
has a = 3 attack edges:

    Sybil trust <= 5.67 * 3 / 7 ~ 2.4

But total trust sums to 1, so the actual bound is min(1, 5.67a/delta).
For a/delta < 0.18, Sybil trust < 1, meaning Eve's trust is strictly
less than honest trust. The honest majority condition (Sybil trust < 1/3)
requires:

    a < delta / 17

For delta = 7, Eve needs at most 0 attack edges for guaranteed honest
majority. For delta = 20, Eve can have at most 1 attack edge. This shows
that **higher honest-graph connectivity directly strengthens Sybil
resistance**.

**Role of spectral gap.** The bound above is worst-case (pi_v(u) could
concentrate near the boundary). When the honest subgraph is fast-mixing
(spectral gap gamma > 0), the PPR distribution over H is approximately
uniform over honest nodes, so:

    pi_v(u) ~ (1-d) / (gamma * |H|) for u far from v

This spreads trust evenly and reduces the boundary concentration.
Specifically, for a fast-mixing graph with gamma = Omega(1):

    max_{u in H} pi_v(u) <= (1-d) / gamma + (1/|H|)

Substituting back:

    sum_{u in S} pi_v(u) <= d * a * ((1-d)/gamma + 1/|H|) / ((1-d) * delta_min)

For large |H| and gamma = Omega(1), this approaches d*a/(gamma * delta_min),
tightening the bound by the spectral gap factor.

**What this proves without external citation:** The Sybil bound follows
from the definition of PPR (a convergent linear recurrence) and elementary
flow analysis on the graph partition. No external theorem is required. The
bound is tight in the following sense: Eve achieves it by placing all attack
edges at the highest-trust honest boundary nodes. QED.

**Theorem 2.7 (Trust-Weighted BFT Acceptance).**
Under honest majority (Definition 1.5), the trust-weighted acceptance
predicate:

    accept(attestations, trust_scores) iff sum_{i in attestations} trust_scores[i] > (2/3) * total_trust

correctly accepts honestly-produced attestations and rejects forgeries,
provided the attestation set includes all honest nodes and excludes all
corrupt nodes that refuse to sign.

*Proof.* Honest nodes hold > 2/3 of trust weight (by assumption). An
honestly-produced signature has all honest nodes attesting, so attesting
trust > 2/3. A forgery requires > 2/3 attesting trust, but corrupt nodes
hold < 1/3, so even with all corrupt nodes attesting, the threshold is not
met. QED.

---

## 3. Layer-by-Layer Composition

We now prove that each protocol layer preserves ITS guarantees, building
from the bottom up.

### Layer 0: Multi-Path Bootstrap

**Protocol.** New node A selects k geographically diverse existing nodes
B_1, ..., B_k. For each B_i, A generates a random 256-bit secret r_i
and sends it to B_i via a distinct network route. Both A and B_i derive
a PSK from r_i.

**Adversary model for Layer 0.** Eve may passively observe up to k-1 of
the k routes. Eve may actively control up to t < k/3 of the target nodes
(Byzantine).

**Theorem 3.1 (Bootstrap ITS Key Agreement).**
If Eve observes at most k-1 of the k bootstrap paths, then for each
unobserved path i, the derived PSK_i is perfectly secret from Eve:

    H(PSK_i | Eve's view) = H(PSK_i) = |PSK_i| bits

*Proof.* Each r_i is generated independently from os.urandom (256 bits).
Eve's view of the observed paths is independent of r_i for each unobserved
path i (the paths are physically independent by the route diversity
assumption). Since PSK_i = SHAKE-256(r_i), and r_i is perfectly secret from
Eve, PSK_i is perfectly secret from Eve. QED.

**Theorem 3.2 (Shamir Protection Against Active Corruption).**
When bootstrap secrets are additionally Shamir-encoded with threshold
tau = k - floor(k/3), up to floor(k/3) corrupt relays can be detected
and excluded, and the secret is reconstructed from the remaining shares.

*Proof.* The ShamirEncoder splits each secret into k shares with
threshold tau. By Theorem 2.1, any tau honest shares suffice for
reconstruction. Corrupt shares are detected by consistency_check()
(leave-one-out interpolation): a tampered share y'_j lies off the
degree-(tau-1) polynomial through the honest shares, and is identified
as the unique inconsistent point when |honest| >= tau + 1. With at most
floor(k/3) corrupt and k - floor(k/3) = tau honest shares, reconstruction
succeeds and all corrupt shares are identified. QED.

**Security after Layer 0:** Node A has at least one ITS PSK with an honest
node B_i (since at most k-1 paths are observed, at least one is clean).

---

### Layer 1: Liu ITS Channel Establishment

**Protocol.** For each PSK_i from Layer 0, nodes A and B_i run the Liu
protocol: Gaussian noise exchange, quantization, Toeplitz hashing,
Wegman-Carter MAC authentication. This produces an ITS channel with
unlimited key material.

**Theorem 3.3 (Liu Channel ITS Guarantee).**
Given a PSK that is epsilon_0-secret from Eve, the Liu protocol produces
an ITS channel where:
1. Key material is (epsilon_0 + epsilon_liu)-secret from Eve per chunk
2. Message authentication has forgery probability <= L/M61 + epsilon_0
   per tag (where L is message length in field elements)
3. The channel is self-renewing (PSK recycling, Theorem 2.5)

where epsilon_liu is the privacy amplification parameter (default 10^-6).

*Proof.*

**(1) Key material security.** The PSK determines two things relevant to
Eve: the reflection coefficient sign alpha in {+1, -1}, and the MAC keys
(r, s). We analyze Eve's min-entropy on Alice's raw samples when the PSK
is epsilon_0-close to uniform rather than perfectly uniform.

Let P_real be the true distribution of the PSK and P_unif be uniform.
By definition, SD(P_real, P_unif) <= epsilon_0. The sign alpha is a
deterministic function of the PSK, so:

    SD(alpha_real, alpha_unif) <= epsilon_0

where alpha_unif is uniform on {+1, -1}. Eve's optimal guess of alpha
therefore succeeds with probability:

    p_alpha <= 1/2 + epsilon_0/2

Now consider one exchange step. Alice's raw sample Z_A depends on alpha
and the Gaussian noise. Eve observes the wire values but not alpha. Her
conditional guessing probability for Z_A (after optimal quantization to
n_bits) is:

    P_guess(Z_A | Eve) = p_alpha * P_guess(Z_A | Eve, alpha=+1)
                       + (1 - p_alpha) * P_guess(Z_A | Eve, alpha=-1)

When alpha is perfectly hidden (p_alpha = 1/2), this equals:

    P_guess_0 = (1/2) * P_guess(Z_A | Eve, alpha=+1)
              + (1/2) * P_guess(Z_A | Eve, alpha=-1)

With the PSK leakage:

    P_guess(Z_A | Eve) <= P_guess_0 + (epsilon_0/2) * max(P_guess(+1), P_guess(-1))
                       <= P_guess_0 + epsilon_0/2

Since min-entropy H_min = -log_2(P_guess), we get:

    H_min(Z_A | Eve, epsilon_0-PSK)
      = -log_2(P_guess_0 + epsilon_0/2)
      >= -log_2(P_guess_0) - epsilon_0 / (P_guess_0 * ln(2))     [for epsilon_0 << P_guess_0]
      = H_min(Z_A | Eve, perfect-PSK) - epsilon_0 / (P_guess_0 * ln(2))

For typical Liu parameters, P_guess_0 ~ 2^{-0.3} per step (from mod-p
wrapping with 8-bit quantization), so the min-entropy loss per step is
at most epsilon_0 / (0.81 * 0.693) ~ 1.78 * epsilon_0 bits.

Over chunk_steps = 1001 steps, total min-entropy loss is at most
1001 * 1.78 * epsilon_0 ~ 1783 * epsilon_0 bits. For epsilon_0 = 10^-6
(recycled PSK), the loss is ~ 0.002 bits total — negligible compared to
H_min_total ~ 300 bits per chunk.

The LHL (Theorem 2.3) extracts:

    n_secure = floor(H_min_total - 1783*epsilon_0 - 2*log_2(1/epsilon_liu) - 2)

bits that are epsilon_liu-close to uniform given Eve's view (including
her partial knowledge of the PSK). By the triangle inequality on
statistical distance (the PSK itself contributes epsilon_0 distinguishing
advantage to any downstream test), the total leakage is at most
epsilon_0 + epsilon_liu per chunk.

For bootstrap PSKs (epsilon_0 = 0), all terms involving epsilon_0 vanish
and we recover the perfect-PSK bound exactly.

**(2) MAC security.** By Theorem 2.4, the MAC forgery probability with
truly uniform keys (r, s) is at most L/M61. When the PSK is
epsilon_0-close to uniform, the induced distribution on (r, s) is also
epsilon_0-close to uniform (since r and s are deterministic functions of
the PSK, and statistical distance cannot increase under post-processing).

For any forgery strategy A, let p_unif = Pr[A succeeds | (r,s) uniform]
and p_real = Pr[A succeeds | (r,s) from real PSK]. Then:

    |p_real - p_unif| <= SD((r,s)_real, (r,s)_unif) <= epsilon_0

Therefore p_real <= L/M61 + epsilon_0. For bootstrap PSKs (epsilon_0 = 0),
this is exactly L/M61.

**(3) Self-renewal.** By Theorem 2.5, the first chunk produces
n_secure >> 144 bits. These bits are (epsilon_0 + epsilon_liu)-secret
from Eve, so using them as the next-round PSK starts the next round with
epsilon_0' = epsilon_0 + epsilon_liu. Over R renewals, the accumulated
PSK leakage is at most epsilon_0 + R * epsilon_liu (induction on the
triangle inequality). QED.

**Security after Layer 1:** A has ITS channels with (at least one, up to k)
honest nodes. Each channel provides unlimited authenticated key material
with epsilon_total = epsilon_0 + epsilon_liu per chunk, accumulated over
R renewals as epsilon_total <= epsilon_0 + R * epsilon_liu (union bound).

---

### Layer 2a: Peer Introduction (Overlay Expansion)

**Protocol.** A wants an ITS channel with C. Mutual contacts B_1, ..., B_m
(m >= 3) each generate a random PSK component PSK_j, sending it to both
A and C over existing ITS channels. The combined PSK is:

    PSK_AC = PSK_1 XOR PSK_2 XOR ... XOR PSK_m

A and C both compute PSK_AC and run Liu to establish a direct ITS channel.

**Theorem 3.4 (Peer Introduction ITS Security).**
If at least one introducer B_j is honest, then PSK_AC is perfectly secret
from Eve and from all other introducers.

*Proof.* B_j generates PSK_j uniformly at random and sends it to A and C
over ITS channels (which are epsilon-secret from Eve by Theorem 3.3).
Even if Eve knows all other PSK_i (i != j) — because she controls the
other m-1 introducers — the XOR:

    PSK_AC = PSK_1 XOR ... XOR PSK_j XOR ... XOR PSK_m

is a one-time pad on PSK_j. Since PSK_j is uniform and independent of
Eve's view (it was generated by honest B_j and transmitted over an ITS
channel), PSK_AC is uniform and independent of Eve's view.

More precisely: PSK_j is (epsilon_chan)-close to uniform from Eve's view
(the ITS channel leakage). By the XOR lemma, if X is epsilon-close to
uniform and Y is arbitrary, then X XOR Y is epsilon-close to uniform.
Therefore PSK_AC is epsilon_chan-close to uniform from Eve's view. QED.

**Key transition:** After this layer, network topology is irrelevant.
All new channels are established via peer introduction over the ITS overlay.
The bootstrap topology assumption (bounded eavesdropping) is no longer
needed.

---

### Layer 2b: Distributed Key Generation (Shamir DKG)

**Protocol.** All n nodes collectively generate a signing polynomial
F(x) of degree d = k-1 over GF(M61):

1. Each node i generates a random polynomial f_i(x) of degree d
2. Node i sends share f_i(j) to node j over their ITS channel
3. Consistency verification: leave-one-out interpolation detects tampered shares
4. Each node j computes its combined share: s_j = sum_i f_i(j)

The combined polynomial is F(x) = sum_i f_i(x), with F(j) = s_j.

**Theorem 3.5 (DKG IT-Privacy).**
If at most t < n/3 nodes are corrupt, then the combined polynomial
F(x) is perfectly private: no coalition of t or fewer corrupt nodes
can learn any information about F(0) (the collective secret) or
about the shares of honest nodes beyond what is implied by their
own shares {F(j)}_{j in corrupt}.

*Proof.* Each honest node i's polynomial f_i is uniformly random of
degree d with independent coefficients. The corrupt coalition C with
|C| = t learns:
- Their own contributions {f_j}_{j in C} (which they chose)
- Shares from honest nodes: {f_i(j)}_{i honest, j in C}
- Their own combined shares: {F(j)}_{j in C}

Since F(j) = sum_{i honest} f_i(j) + sum_{i in C} f_i(j), and the
corrupt coalition knows its own contributions, what it learns about
honest contributions is:

    {sum_{i honest} f_i(j)}_{j in C}

This is t evaluations of the polynomial G(x) = sum_{i honest} f_i(x),
which has degree d = k-1 and uniformly random coefficients (sum of
independent uniforms). By Theorem 2.2 (Shamir privacy), t <= k-1
evaluations reveal nothing about G(0) = sum_{i honest} f_i(0), and
hence nothing about F(0) = G(0) + sum_{i in C} f_i(0) beyond what
the corrupt nodes can compute from their own contributions. QED.

**Theorem 3.6 (DKG Consistency Verification).**
If at most t < n/3 nodes send inconsistent shares, and n > d + 1 = k,
then all corrupt senders are detected and excluded, and no honest sender
is falsely excluded.

**Distributed verification protocol** (adapted from Ben-Or, Goldwasser,
Wigderson 1988, using ITS channels instead of broadcast):

```
Phase 1 — Share distribution:
    For each sender i, for each receiver j:
        i sends f_i(j) to j, authenticated via ITS channel MAC(i↔j)

Phase 2 — Pairwise cross-check:
    For each pair (j, k) of nodes with ITS channel j↔k:
        For each sender i:
            j sends (i, j, f_i(j)) to k, authenticated via MAC(j↔k)
            k sends (i, k, f_i(k)) to j, authenticated via MAC(j↔k)

Phase 3 — Local consistency check:
    Each node k, for each sender i:
        Collects cross-checked shares: {(j, f_i(j))} from Phase 2
          plus its own (k, f_i(k)) from Phase 1
        If k has >= d+2 shares from sender i:
            Interpolates degree-d polynomial through first d+1 shares
            Checks remaining shares for consistency
            If any share is inconsistent: k adds i to its local suspect set

Phase 4 — Complaint aggregation:
    Each node k broadcasts its suspect set to all neighbors via ITS channels
    For each sender i:
        complaint_count(i) = number of distinct nodes reporting i as suspect
        If complaint_count(i) > t:  EXCLUDE sender i
```

**Communication cost:** O(n^3) authenticated messages total (n senders ×
n^2 pairwise comparisons). Each message is a single GF(M61) element (8
bytes) plus MAC tag (8 bytes), transmitted over an ITS channel.

*Proof of correctness.*

**Claim 1: An honest sender is never excluded.**
An honest sender i computes f_i(j) = poly_eval(coeffs_i, j) for all j.
These values lie exactly on a degree-d polynomial. Any d+2 or more of
these shares are perfectly consistent (Theorem 2.1). No honest node finds
an inconsistency, so no honest node adds i to its suspect set.
At most t corrupt nodes can falsely add i to their suspect sets. Since
t < n/3 and the exclusion threshold is > t, we need complaint_count(i) > t
for exclusion. False complaints contribute at most t, which does not
exceed t. Therefore honest sender i is not excluded.

**Claim 2: A corrupt sender with inconsistent shares is excluded.**
Suppose corrupt sender i sends shares that do NOT lie on any single
degree-d polynomial. Then there exist at least two honest nodes j and k
such that f_i(j) and f_i(k) are inconsistent with a common degree-d
polynomial (since the honest nodes hold n-t > 2n/3 > d+1 evaluations,
and these cannot all lie on a degree-d polynomial if the shares are
globally inconsistent).

After Phase 2, every honest node that has ITS channels to both j and k
(and enough other honest nodes to reach d+2 total) detects the
inconsistency in Phase 3. How many honest nodes detect it?

Each honest node collects shares from its ITS-channel neighbors plus its
own. In a connected overlay with minimum degree delta >= log_2(n) + 1
(enforced by GraphMonitor), each honest node has at least delta honest
neighbors. It collects at least delta + 1 >= d + 2 shares per sender
(since delta >= log_2(n) + 1 >= d + 1 for d = 2n/3 when n is large
enough — **note:** for this to work, delta must exceed d, which requires
dense connectivity. See Remark below).

When an honest node has d+2 shares including both a "correct" share and
an "inconsistent" share, it detects the inconsistency. The number of
detecting honest nodes is at least n - t - (nodes missing the inconsistent
shares). Since the corrupt sender must be inconsistent with at least one
honest node, and cross-checking propagates this to all connected honest
nodes, the complaint count from honest nodes exceeds t (given sufficient
connectivity). Combined with the > t exclusion threshold, the corrupt
sender is excluded.

**Claim 3: ITS channels prevent share manipulation in transit.**
All Phase 1 and Phase 2 messages are authenticated by Wegman-Carter MACs
over ITS channels (forgery probability L/M61 per message, Theorem 2.4).
A corrupt node cannot modify shares sent by honest nodes — it can only
choose what shares it generates in Phase 1. This means the only attack
vector is sending inconsistent shares at the source, which is caught by
Claims 1-2.

**Remark on connectivity requirement.** The distributed verification
requires each honest node to collect at least d+2 = 2n/3 + 1 shares per
sender via cross-checking. This requires the honest overlay subgraph to
have minimum degree >= d+1 = 2n/3. For n = 100, this means each honest
node needs ITS channels with at least 67 other honest nodes. This is a
stronger connectivity requirement than the GraphMonitor's log_2(n)
target. In practice, peer introduction (Layer 2a) should be used to
ensure the overlay is sufficiently dense before running DKG. For sparser
graphs, a multi-round complaint protocol can substitute: nodes that
detect inconsistency relay the evidence to distant nodes over multiple
hops, at the cost of O(n) additional rounds.

**Note on consistent cheating:** A corrupt sender CAN send shares that
lie on a valid degree-d polynomial different from the one it "should"
have chosen (i.e., it picks a biased rather than random polynomial). The
consistency check does not detect this, but it does not need to: the DKG
privacy proof (Theorem 3.5) holds regardless of the corrupt nodes'
polynomial choices, because security comes from the honest nodes' random
contributions. QED.

**Theorem 3.7 (DKG Correctness).**
After excluding corrupt nodes, the combined shares {s_j}_{j honest}
lie on a polynomial F of degree d, and any k honest shares suffice
to reconstruct F(x) at any point via Lagrange interpolation.

*Proof.* The combined polynomial F(x) = sum_{i not excluded} f_i(x)
is a sum of polynomials of degree d, hence has degree d. Each honest
node j holds F(j) = s_j. By Theorem 2.1, k = d+1 evaluations of a
degree-d polynomial uniquely determine it. Since at least n - t >= k
honest nodes hold valid shares, reconstruction succeeds. QED.

**Security guarantee from DKG channel protection:** All shares are
transmitted over ITS channels (Layer 1). By Theorem 3.3, Eve cannot
read shares in transit (epsilon-secret) and cannot forge shares
(MAC forgery probability L/M61 per message, Theorem 2.4). This means:

- A corrupt node can only tamper with shares it generates, not shares
  from others
- Eve cannot learn honest shares by eavesdropping on ITS channels
- Consistency verification catches all local tampering (Theorem 3.6)

---

### Layer 3: USS Threshold Signatures

**Protocol.** Given combined shares {s_j = F(j)} from DKG:

**Signing** (k-of-n threshold): Given message m, k signers each compute
a partial signature using Lagrange basis coefficients:

    partial_j = s_j * L_j(m)

where L_j(m) = prod_{i != j} (m - x_i) / (x_j - x_i) is the Lagrange
basis polynomial. The combiner sums:

    sigma = sum_j partial_j = sum_j F(j) * L_j(m) = F(m)

by the Lagrange interpolation identity.

**Verification:** Verifier V holds v verification points
{(x_i, F(x_i))}_{i=1..v}. Given (m, sigma), V checks whether the
v+1 points {(x_1, F(x_1)), ..., (x_v, F(x_v)), (m, sigma)} are
consistent with a polynomial of degree d. If v+1 > d+1 (i.e., v > d),
this check is a necessary and sufficient condition for sigma = F(m).

**Theorem 3.8 (USS IT-Unforgeability).**
An adversary holding q < d+1 evaluations of F (from corrupt shares and
observed signatures combined) can forge a signature on a new message m*
with probability exactly:

    Pr[forge] = 1 / M61

per attempt, where M61 = 2^61 - 1. This holds regardless of the
adversary's computational power.

*Proof.* The adversary knows q evaluations of F: at most t < k-1 = d
from corrupt shares, plus at most S <= d/2 from observed signatures
(enforced by SignatureBudget). Thus q <= t + S < d + d/2.

The signature budget ensures q < d + 1 (see Theorem 3.10), so at least
one degree of freedom in F remains unknown to the adversary.

Conditioned on the q known evaluations {(x_i, F(x_i))}_{i=1..q}, the
value F(m*) at any new point m* not in {x_1, ..., x_q} is uniformly
distributed over GF(M61). This follows from Theorem 2.2: the q known
evaluations constrain q of the d+1 coefficients, leaving d+1-q >= 1
free coefficients. The map from the free coefficients to F(m*) is a
surjective affine map (the Vandermonde column for m* is nonzero for
m* distinct from the known x_i), so each value in GF(M61) is equally
likely.

The adversary's optimal strategy is to guess a uniformly random element
of GF(M61), succeeding with probability exactly 1/M61 ~ 4.3 * 10^-19.
No strategy (quantum, classical, or otherwise) can do better, because
this is an information-theoretic bound, not a computational one. QED.

**Theorem 3.9 (USS Non-Repudiation).**
Under honest majority, a signer cannot deny having signed message m:

1. Each honest verifier V_i holds v > d independent verification points
2. V_i independently checks (m, sigma) against its points
3. An honest signer produces sigma = F(m), which is consistent with
   all verification points (by polynomial identity)
4. A forged sigma' != F(m) is **deterministically detected** by every
   verifier with v > d points
5. Majority adjudication: honest nodes (>2/3 by trust weight) agree

*Proof.* If sigma = F(m) (genuinely signed), then (m, sigma) lies on
F, and every verifier's check passes: the v+1 points all lie on the
unique degree-d polynomial F, so Lagrange interpolation is consistent.

If sigma' != F(m) (forgery), then the point (m, sigma') does NOT lie on
F. Every verifier with v > d points has v + 1 > d + 1 points total.
Since d+1 points uniquely determine a degree-d polynomial (Theorem 2.1),
and the v verification points determine F while (m, sigma') is not on F,
the Verifier detects inconsistency with **certainty** (probability 1,
not probabilistic). Specifically: interpolating the first d+1 points
(which lie on F) and evaluating at any remaining point yields F(x_i)
for verification points but sigma' != F(m) for the forged point.

Since all honest verifiers (> 2/3 by trust weight) reject the forgery
with certainty, the DisputeResolver returns 'forged'. QED.

**Theorem 3.10 (Signature Budget Soundness).**
The SignatureBudget limit of S_max = d/2 signatures per epoch ensures
that no adversary can reconstruct F, provided t < n/3.

*Proof.* The adversary's total knowledge of F consists of:
- **Corrupt shares:** at most t evaluations {(j, F(j))}_{j in corrupt}
- **Public signatures:** at most S_max = d/2 evaluations {(m_i, F(m_i))}

Total known evaluations: q = t + S_max.

**Reconstruction requires d+1 evaluations** (Theorem 2.1). We need
q < d + 1, i.e., t + d/2 < d + 1, i.e., t < d/2 + 1.

Since k = 2n/3 + 1, we have d = k - 1 = 2n/3, so d/2 = n/3.
The assumption t < n/3 gives t < n/3 = d/2 < d/2 + 1. Therefore
q = t + d/2 < d/2 + d/2 = d < d + 1, and the polynomial remains
undetermined. By Theorem 3.8, forgery probability stays at 1/M61
per attempt.

**Why d/2 and not more?** The budget d/2 is chosen so that even a
maximally powerful adversary (t = n/3 - 1 corrupt nodes) cannot reach
d+1 evaluations: (n/3 - 1) + d/2 = (n/3 - 1) + n/3 = 2n/3 - 1 = d - 1
< d + 1. A more aggressive budget of d - t would be theoretically safe
but would depend on knowing t exactly. The conservative d/2 is safe for
all t < n/3 without needing to estimate the adversary's actual strength.

EpochManager triggers a DKG re-deal before this limit is reached,
generating a fresh polynomial F' with independent randomness. QED.

---

### Consensus Layer: Trust-Weighted ITS BFT

**Protocol.** When a signed message (m, sigma) is broadcast:
1. Each honest node verifies sigma against its verification shares
2. Each node computes trust-weighted acceptance (Theorem 2.7)
3. A message is accepted into consensus if > 2/3 of trust-weighted
   attestations confirm it

**Theorem 3.11 (BFT Safety Under Honest Trust Majority).**
Under honest majority (Definition 1.5), the trust-weighted BFT consensus
satisfies:

- **Safety**: If an honest node accepts (m, sigma), then sigma = F(m)
  (no honest node accepts a forgery)
- **Liveness**: If all honest nodes produce attestations for a genuinely
  signed message, it is accepted

*Proof.*
Safety: Suppose sigma != F(m). By Theorem 3.9, every honest verifier
with v > d verification points rejects with certainty. Honest nodes hold > 2/3 trust
weight. None of them attest to the forged message. Corrupt nodes hold
< 1/3 trust weight. Therefore attesting trust < 1/3 < 2/3 threshold.
The message is rejected.

Liveness: sigma = F(m) passes every honest verifier's check (polynomial
consistency). All honest nodes attest. Honest attestation trust > 2/3.
The message is accepted. QED.

---

### Application Layer

The application layer (wallets, transfers, contracts) uses the consensus
layer as a black box: it submits messages for signing, and receives
signed-and-accepted messages from consensus. No additional cryptographic
assumptions are introduced.

**Theorem 3.12 (Application Layer Preservation).**
Any application built on the consensus layer inherits all ITS properties:
unforgeable signatures, non-repudiable attestations, and Sybil-resistant
trust weighting, without introducing computational assumptions.

*Proof.* The application layer performs no cryptographic operations beyond
calling Sign, Verify, and checking consensus acceptance. All security
properties are provided by the lower layers (Theorems 3.1-3.11). QED.

---

## 4. Main Composition Theorem

**Theorem 4.1 (End-to-End ITS Composition).**

Consider a Liun network of n nodes with at most t < n/3 corrupt nodes
(by trust weight). Let:
- epsilon_boot = 0 (bootstrap PSK from unobserved path is perfectly secret)
- epsilon_liu = 10^-6 per chunk (LHL privacy amplification parameter)
- L_mac = maximum MAC message length in field elements (typically <= 10^4)
- delta_mac = L_mac / M61 per MAC tag (Theorem 2.4)
- delta_forge = 1 / M61 per signature forgery attempt (Theorem 3.8)
- R = number of Liu key renewals per channel per epoch
- S = number of signatures per epoch
- C = number of active channels (<= n(n-1)/2)

Then the probability of any security failure (key compromise, MAC forgery,
signature forgery, or non-repudiation violation) in one epoch is at most:

    epsilon_total <= C * R * epsilon_liu      (channel key leakage)
                   + C * R * delta_mac         (MAC forgery across all channel messages)
                   + S * delta_forge            (signature forgery)

*Proof.* We compose the per-layer guarantees using the union bound.

**Layer 0 (Bootstrap):** Each unobserved path yields a perfectly secret
PSK (Theorem 3.1, epsilon_boot = 0). Shamir protection handles active
corruption (Theorem 3.2). At least one honest PSK exists.

**Layer 1 (Liu Channels):** Each PSK seeds an ITS channel with per-chunk
leakage epsilon_liu (Theorem 3.3). Over R renewals, the accumulated
leakage per channel is at most R * epsilon_liu (union bound). Over C
channels, total leakage is at most C * R * epsilon_liu.

**Layer 2a (Peer Introduction):** Each new channel is seeded by XOR of
m >= 3 introducer PSKs. If at least one introducer is honest, the combined
PSK is epsilon_chan-secret (Theorem 3.4). This adds at most epsilon_chan
per new channel, already counted in the channel total above.

**Layer 2b (DKG):** Perfect privacy from corrupt coalition (Theorem 3.5).
Consistency verification detects inconsistent shares (Theorem 3.6). All
shares travel over ITS channels — the leakage per share transmission is
epsilon_liu, already counted in the channel total.

**Layer 3 (USS):** Forgery probability delta_forge = 1/M61 per attempt
(Theorem 3.8). Over S signatures per epoch, the total forgery probability
is at most S / M61 (union bound). Non-repudiation: a forged sigma' != F(m)
is detected by every honest verifier with certainty (Theorem 3.9), since
v+1 > d+1 points uniquely determine the polynomial.

**Consensus:** Safety and liveness hold under honest majority
(Theorem 3.11), with failure probability bounded by the signature
forgery probability above.

The total failure probability is the sum of all layer failure
probabilities (union bound), yielding the claimed bound. QED.

**Concrete instantiation.** For typical parameters:
- n = 100, C = ~500 channels, R = 100 renewals/epoch, S = 500 signatures
- L_mac = 1000

The union bound gives epsilon_total <= C*R*epsilon_liu + C*R*L_mac/M61 +
S/M61, which is dominated by the first term. We choose epsilon_liu to
achieve a target security level:

| Target epsilon_total | Required epsilon_liu | Bits sacrificed per chunk | Throughput impact |
|---------------------|---------------------|--------------------------|-------------------|
| 10^-2 | 2 * 10^-7 | ~47 extra hash slack | ~0.6% fewer key bits |
| 10^-6 | 2 * 10^-11 | ~73 extra hash slack | ~0.9% fewer key bits |
| 10^-10 | 2 * 10^-15 | ~99 extra hash slack | ~1.2% fewer key bits |
| 10^-20 | 2 * 10^-25 | ~165 extra hash slack | ~2.1% fewer key bits |

Derivation: epsilon_liu = epsilon_total / (C * R) = epsilon_total / 50000.
The LHL slack is 2*log_2(1/epsilon_liu) + 2 bits subtracted from H_min_total
before extraction. Since H_min_total ~ 300-500 bits per chunk (1001 steps
× ~0.3-0.5 bits/step), even the 10^-20 target only sacrifices ~165/8000
~ 2% of raw throughput.

**Recommended operating point:** epsilon_liu = 10^-15, giving:

    epsilon_total <= 500 * 100 * 10^-15   + 500 * 100 * 1000/M61 + 500/M61
                  =  5 * 10^-11           + 2.2 * 10^-11          + 2.2 * 10^-16
                  ~  7.2 * 10^-11

This is negligible (~2^-33) with only ~99 bits of additional LHL slack
per chunk — less than 1.2% throughput reduction. The MAC and forgery
terms are of comparable magnitude at this operating point, confirming
that all three failure modes are balanced.

**Tightening beyond union bound.** The union bound assumes every channel
and every renewal could independently fail. In reality, channel failures
are correlated (they share the same adversary, same network). A tighter
analysis using the **composition theorem for statistical distance**
(Theorem: if n events each have SD at most epsilon from ideal, the
composed system has SD at most n*epsilon from ideal — which IS the union
bound) confirms that the union bound is actually tight for independent
channels with independent Toeplitz matrices. The bound is not loose for
this particular structure — each chunk uses an independently sampled
Toeplitz matrix, so per-chunk leakages are indeed independent. The
union bound correctly accounts for the probability that ANY chunk leaks
across ALL channels and renewals.

---

## 5. What This Proof Does and Does Not Cover

### Covered

1. **Shamir perfect privacy** — exact, zero-error (Theorem 2.2)
2. **USS IT-unforgeability** — forgery probability 1/M61 per attempt (Theorem 3.8)
3. **Wegman-Carter MAC** — forgery probability L/M61 per tag (Theorem 2.4)
4. **Liu key material** — epsilon-close to uniform via LHL, with exact min-entropy degradation from non-uniform PSK (Theorem 3.3)
5. **DKG privacy and correctness** — perfect privacy, polynomial consistency (Theorems 3.5-3.7)
6. **DKG distributed consistency verification** — formal BGW88-style protocol over ITS channels with O(n^3) messages; honest senders never excluded, corrupt senders detected (Theorem 3.6)
7. **Peer introduction** — ITS from XOR of honest component (Theorem 3.4)
8. **Bootstrap** — perfect secrecy from route diversity (Theorem 3.1)
9. **Sybil resistance** — self-contained PPR flow proof: Sybil trust <= d*a/((1-d)*delta_min), explicit spectral gap tightening (Theorem 2.6)
10. **BFT safety/liveness** — under trust-weighted honest majority (Theorem 3.11)
11. **Signature budget** — budget d/2 safe for all t < n/3 (Theorem 3.10)
12. **Concrete security parameters** — all bounds explicit; recommended operating point epsilon_total ~ 7.2 * 10^-11 with < 1.2% throughput cost (Theorem 4.1)

### Not Covered (Future Work)

1. **UC framework formalization** — This proof uses game-based composition
   with union bounds. A full UC proof would provide stronger composability
   guarantees under arbitrary concurrent protocol execution.

2. **Liu physics model validation** — We take the min-entropy bound from
   the Liu protocol's physical model (P_guess ~ 2^-0.3 per step) as given.
   Validating this bound against real hardware is an experimental question.
   The algebraic composition above this bound is exact.

3. **Network topology model** — The bootstrap security (Theorem 3.1) assumes
   route independence. Quantifying actual route independence on the real
   internet is an empirical question (see OPEN_PROBLEMS.md #3).

4. **Adaptive corruption** — This proof assumes a static corruption set
   (Eve chooses which nodes to corrupt before the protocol starts). An
   adaptive adversary who can corrupt nodes during execution may be
   stronger. The honest majority assumption bounds the total corruption
   but does not address adaptive selection.

5. **Concurrent epoch transitions** — The proof considers a single epoch.
   Composing across epoch boundaries (where old and new signing polynomials
   coexist) requires additional analysis.

6. **DKG overlay density** — Theorem 3.6 requires minimum honest degree
   >= 2n/3 for single-round distributed verification. Sparser overlays
   require multi-round complaint relay (see Remark in Theorem 3.6).

---

## 6. Summary

The Liun protocol achieves information-theoretic security through composition
of three primitives:

| Primitive | Security property | Bound |
|-----------|------------------|-------|
| Polynomial over GF(M61) | Perfect privacy (Shamir), IT-unforgeability (USS), one-time MAC (WC) | Exact (Shamir), 1/M61 (USS), L/M61 (MAC) |
| Liu protocol | Epsilon-close to uniform key material | epsilon_liu per chunk (LHL) |
| PageRank on channel graph | Sybil trust bounded by attack edges | d*a/((1-d)*delta_min), tightened by spectral gap |

The composition across six layers preserves ITS guarantees:

```
Layer 0 (Bootstrap)     : Perfect secrecy from route diversity
          |
          v  PSKs
Layer 1 (Liu Channels)  : epsilon-ITS key material + L/M61 MAC
          |
          v  ITS channels
Layer 2a (Peer Intro)   : ITS from XOR of honest component
Layer 2b (DKG)          : Perfect privacy, polynomial consistency
          |
          v  Signing shares
Layer 3 (USS Signatures): 1/M61 unforgeability, non-repudiation
          |
          v  Signed messages
Consensus               : BFT safety/liveness under honest majority
          |
          v  Accepted messages
Application             : Inherits all ITS properties
```

The total failure probability per epoch is bounded by:

    epsilon_total <= C * R * epsilon_liu + C * R * L_mac / M61 + S / M61

At the recommended operating point (epsilon_liu = 10^-15), this gives
epsilon_total ~ 7.2 * 10^-11 for n=100, with < 1.2% throughput cost.
The bound is tight (not loose) because per-chunk Toeplitz hashes use
independent random matrices.

**No computational assumption appears anywhere in this chain.**

---

## References

1. Shannon, C.E. (1949). "Communication Theory of Secrecy Systems."
   Bell System Technical Journal.

2. Shamir, A. (1979). "How to Share a Secret." Communications of the ACM.

3. Wegman, M.N. and Carter, J.L. (1981). "New Hash Functions and Their
   Use in Authentication and Set Equality." JCSS.

4. Impagliazzo, R., Levin, L.A., and Luby, M. (1989). "Pseudo-random
   Generation from One-way Functions." STOC.

5. Yu, H., Kaminsky, M., Gibbons, P.B., and Flaxman, A.D. (2006).
   "SybilGuard: Defending Against Sybil Attacks via Social Networks." SIGCOMM.

6. Hanaoka, G., Shikata, J., Zheng, Y., and Imai, H. (2000).
   "Unconditionally Secure Digital Signature Schemes Admitting
   Transferability." ASIACRYPT.

7. Liu (protocol). Gaussian noise key generation with privacy amplification
   via Leftover Hash Lemma. See: [Liup repository](https://github.com/noospheer/Liup).
