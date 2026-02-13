# Protocol 06: Local Trust via Personalized PageRank

## Purpose

Provide Sybil resistance and consensus weighting without computational
hardness assumptions, founding members, or global authority.

---

## Core Mechanism

Each node computes trust scores for all other nodes from **its own
perspective** using a random walk on the Liu channel graph.

### The Graph

- **Nodes**: every participant in the Liun network
- **Edges**: active Liu channels between pairs of nodes
- **Edge weight**: optional — can weight by channel age, bandwidth, or
  key material throughput

The graph is constructed locally by each node from its own channel
relationships and gossip about the broader topology (received over
ITS channels).

### Personalized PageRank

Node A computes trust for all other nodes via:

```
trust_A(v) = (1 - d) * seed_A(v) + d * Σ_u [trust_A(u) * w(u,v) / out(u)]
```

Where:
- `d` = damping factor (0.85 typical, tunable)
- `seed_A(v)` = 1 if v == A, else 0 (A is its own trust seed)
- `w(u,v)` = edge weight from u to v
- `out(u)` = total outgoing edge weight from u

This is standard personalized PageRank, computable by power iteration.
Converges in O(log N) iterations for well-connected graphs.

### Why This Works Against Sybil

**The attack:**
```
Eve creates 1000 fake nodes: S1, S2, ..., S1000
Eve connects them densely to each other
Eve has 3 channels to honest nodes (attack edges)
```

**The defense:**
```
Honest node A computes trust_A:
  - Random walk from A reaches Eve's cluster only through 3 attack edges
  - Total trust flowing into Eve's entire cluster ≈ trust of 3 honest nodes
  - 1000 Sybils share this tiny trust allocation
  - Each Sybil node has mass ≈ 3/1000 of an honest node

Consensus weight of Eve's 1000 nodes ≈ weight of 3 honest nodes
```

The formal bound (Yu et al. 2006, SybilRank):
> Total trust assigned to a Sybil region is O(g), where g is the number
> of attack edges, **regardless of the number of Sybil nodes**.

### No Founding Members

Each node seeds PageRank from itself. There is no global "trusted set"
or founding committee. Trust is:
- **Local**: different nodes compute different trust scores
- **Subjective**: A's trust for C may differ from B's trust for C
- **Emergent**: trust stabilizes as the graph grows and mixes

### Trust in Consensus

When counting votes for BFT consensus:
- Do NOT count nodes equally (one-node-one-vote is trivially Sybil-broken)
- Weight each node's vote by the voter's trust in that node
- Threshold: proposal accepted when trust-weighted agreement > 2/3

```
For node A deciding whether to accept block B:
  supporters = nodes that signed/attested B
  weight = Σ_s [trust_A(s)] for s in supporters
  accept if weight > 2/3 * Σ_all [trust_A(v)]
```

---

## Parameters

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| Damping factor (d) | 0.85 | Standard PageRank default, proven effective |
| Walk length | ~20 steps | Sufficient for convergence in well-mixed graphs |
| Recomputation interval | Every epoch | Trust updates as channels form/drop |
| Minimum channel age for full weight | 0 (instant) | No artificial delay — weight grows naturally |
| Edge weight function | Uniform (v1) | Can later weight by bandwidth/age |

---

## Threat Analysis

### What Local Trust Solves

| Threat | How it's bounded |
|--------|-----------------|
| Sybil flooding (many fake nodes) | Trust bounded by attack edges, not node count |
| Puppet voting (fake nodes all vote same way) | Combined trust of all puppets ≈ trust of a few honest nodes |
| Identity farming (create and abandon) | Abandoned nodes lose channels, lose trust |

### What Local Trust Does NOT Solve

| Threat | Why | Mitigation |
|--------|-----|------------|
| Slow infiltration | Eve builds real channels over months | Bounded by honest nodes' channel capacity; detectable by graph monitoring |
| Liveness attack (>1/3 trust stall) | If Eve achieves >1/3 trust-weighted, can stall consensus | Same vulnerability as every BFT system including Ethereum |
| Cold start (few nodes) | Small graph doesn't mix well | Trust converges as network grows; bootstrap from diverse geography |

---

## Graph Properties Required

For personalized PageRank to provide strong Sybil resistance, the honest
subgraph must be:

1. **Connected**: there exists a path between any two honest nodes
   (guaranteed by overlay expansion — Protocol 02)

2. **Fast mixing**: random walks on the honest subgraph converge quickly
   to the stationary distribution. This depends on:
   - Graph expansion (spectral gap)
   - Absence of extreme bottlenecks
   - Sufficient edge density

3. **Sparse attack boundary**: the number of edges between honest and
   Sybil regions (attack edges) should be small relative to internal edges

**Research needed:** Measure these properties on simulated Liu channel
graphs at 100, 1000, and 10000 nodes.

---

## Comparison

| Approach | Computation? | Founders? | Sybil bound |
|----------|-------------|-----------|-------------|
| Proof of Work | Yes (breaks ITS) | No | Hash rate |
| Proof of Stake | Economic | No | Capital |
| Federated trust | No | Yes (centralized) | Federation size |
| **Local trust (this)** | **No** | **No** | **Attack edges** |

---

## Implementation Notes

### Data Structures

```python
# Graph representation
channels: Dict[NodeID, Set[NodeID]]   # adjacency list
weights: Dict[(NodeID, NodeID), float] # edge weights (optional)

# Trust computation
def personalized_pagerank(seed: NodeID, graph, d=0.85, iterations=20):
    """Compute trust scores from seed's perspective."""
    trust = {node: 0.0 for node in graph}
    trust[seed] = 1.0
    for _ in range(iterations):
        new_trust = {}
        for v in graph:
            incoming = sum(
                trust[u] * weight(u, v) / out_degree(u)
                for u in neighbors_of(v)
            )
            new_trust[v] = (1 - d) * (1.0 if v == seed else 0.0) + d * incoming
        trust = new_trust
    return trust
```

### Integration with Consensus

```python
def accept_block(self, block, attestations):
    """Trust-weighted BFT acceptance."""
    my_trust = self.personalized_pagerank(self.node_id)
    total_trust = sum(my_trust.values())
    attesting_trust = sum(my_trust[a] for a in attestations)
    return attesting_trust > (2/3) * total_trust
```

---

## References

- Yu, H., Kaminsky, M., Gibbons, P.B., & Flaxman, A. (2006).
  "SybilGuard: Defending Against Sybil Attacks via Social Networks."
  ACM SIGCOMM.

- Yu, H., Gibbons, P.B., Kaminsky, M., & Xiao, F. (2008).
  "SybilLimit: A Near-Optimal Social Network Defense against Sybil Attacks."
  IEEE S&P.

- Cao, Q., Sirivianos, M., Yang, X., & Pregueiro, T. (2012).
  "Aiding the Detection of Fake Accounts in Large Scale Social Online Services."
  NSDI.

- Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).
  "The PageRank Citation Ranking: Bringing Order to the Web."
  Stanford InfoLab.
