# Peer Discovery via Kademlia DHT

How `liun-node` daemons find each other on the network, and why the discovery
layer survives a computational-crypto break.

## Threat-model framing

Liun's premise is that all computational crypto can be broken (post-quantum,
factoring/discrete-log advances, etc.). The discovery layer therefore has to
work in a world where *signatures, MACs based on hash assumptions, TLS, DNSSEC,
and ECDH key exchange are all gone*.

**The DHT does not try to be cryptographically authenticated.** Entries are
*hints*: "node X is rumored to be at address Y." Authenticity is established
*after* the lookup, when the channel layer dials Y and runs the Liun ITS
handshake. If Y is wrong (fake address, attacker IP, stale), the handshake
fails (no MAC verification possible without the real shared key) and the
caller retries with the next candidate. The cost of DHT poisoning collapses
to "discoverability nuisance" — never confidentiality, never impersonation.

This is the architectural choice that lets the DHT use **no cryptography
whatsoever**, which means there's nothing in it for a future crypto break to
take away.

## Wire protocol (UDP, plain binary)

```
Frame header (56 bytes):
  [version: 1][kind: 1][txn_id: 4][sender_id: 48][sender_channel_port: 2][payload]

Kinds:
  0x01 PING        — payload empty
  0x02 PONG        — payload empty
  0x03 FIND        — payload: target_id[48]
  0x04 NODES       — payload: count[1] + count × Contact

WireContact (per entry in NODES):
  [id: 48][family: 1][addr: 4 or 16][udp_port: 2][channel_port: 2]
```

`sender_channel_port` is the TCP port the sender listens on for Liun channel
handshakes. The DHT-side UDP port is *observed* from the packet source — never
self-reported. This separation is critical: it means a peer can run DHT on
one port and Liun channel TCP on another, and the discovery layer carries
both addresses correctly.

No checksums beyond UDP's own. No signatures. No optional encryption layer.
The Liun ITS handshake at the destination is the only authentication.

## Routing table

384 k-buckets (one per bit of XOR distance), K=20 contacts per bucket.

- **XOR distance**: `d(a, b) = a ⊕ b`. Symmetric, deterministic, well-defined.
- **Bucket index**: position of the highest set bit of the XOR, MSB-first.
  Closer nodes land in lower-index buckets.
- **Eviction**: when a bucket fills, the oldest contact is candidate for
  removal; in practice we keep existing live contacts (Kademlia pessimism)
  and reject new ones unless an existing one fails a ping.

Routing table size: `O(K · log N)` ≈ 400 entries at 1B nodes (~30 KB of state).

## Iterative FIND_NODE (Kademlia lookup)

```
function find_node(target):
    candidates ← K closest known contacts to target
    queried ← {self}
    loop:
        round ← α=3 closest unqueried candidates
        if round empty: break
        send FIND(target) to each in round in parallel
        for each response:
            add new contacts to routing table and candidate set
        if closest distance to target didn't improve: break
    return K closest known contacts to target
```

Latency: O(log N) rounds, each one parallel RPC roundtrip. Empirical: ~100µs
on a 20-node localhost mesh.

## Joining a network

```
1. Parse config.toml → list of [[dht_seeds]] (each: id + addr)
2. For each seed: PING. If responsive, add to routing table.
3. Issue FIND(self_id) — pulls our K closest neighbors into the table.
4. Periodic refresh (every 5 min): re-issue FIND(self_id), persist table to disk.
```

Bootstrap requires *one* reachable seed in the config. Subsequent runs use
`~/.liun/dht_peers.bin` (saved during refresh) and don't need seeds at all
unless the cached peers have all gone offline.

## Persistence

`~/.liun/dht_peers.bin` (binary little-endian):

```
[count: u64]
  [id: 48][family: 1][addr: 4 or 16][udp_port: 2][channel_port: 2]
  ...
```

Saved every 5 minutes during the periodic refresh task; loaded on startup
*before* contacting seeds. After the first successful session, the node has
its own working peer list and seeds become optional.

## Address scheme: UDP for DHT, TCP for channel

Each peer effectively has *two* addresses on the same IP:

- A **DHT address** (UDP socket) — `dht_addr` in `Contact`
- A **channel address** (TCP socket) — same IP, port = `channel_port`

The two transports can use the same port number (UDP and TCP sockets are
independent in the kernel) or different ports. The DHT lookup result includes
both, so the channel layer always dials the right TCP port.

## Operating a node

The fastest way to a working config is the `init` wizard:

```bash
liun-node --data-dir ~/.liun init             # interactive prompts
liun-node --data-dir ~/.liun init --defaults  # accept defaults, no prompts
liun-node --data-dir ~/.liun init --force     # overwrite existing config
```

It generates `identity.toml` (your Node ID) and `config.toml`, then prints the
exact command to start the node. The interactive flow walks you through
adding DHT seeds (paste their `(id, addr)` pairs).

If you'd rather hand-edit, the schema is straightforward:

```toml
# config.toml
sigma_over_p   = 2.0
batch_size     = 100000
bootstrap_peers = []
n_nodes        = 10

# Optional DHT seeds (each is a known existing node's id + UDP address).
# Both peers in a mesh need consistent identity → addr mappings, but the
# seed list isn't a secret — it's public bootstrap info.
#
# Node IDs are 384-bit, displayed as base58 (~65 chars). Bitcoin alphabet:
# no 0/O/I/l confusion, no special chars. Hex (96 chars) also accepted via
# the legacy `id_hex = "..."` field name.
[[dht_seeds]]
id   = "4HeK8SZEQXBwm7rXvwbxyJKqqDn18TUvxfnuGNDg7dXK5x5cTZFMFAQaHKzhcVFudJ"
addr = "203.0.113.10:7771"

[[dht_seeds]]
id   = "icYAah8kp9L3wS5efDk5s68AzWfgNRSSWyjfzucY3MEAmeVF1obCb31eza8HSKSz8"
addr = "198.51.100.42:7771"
```

```bash
liun-node \
    --data-dir ~/.liun \
    --listen 0.0.0.0:7771 \           # TCP for Liun channels
    --dht-listen 0.0.0.0:7771 \       # UDP for DHT (same port is fine)
    --config /etc/liun/config.toml
```

Find a specific peer by their node-ID and dial them through DHT:

```bash
liun-node \
    --listen 0.0.0.0:7772 --dht-listen 0.0.0.0:7772 \
    --config /etc/liun/config.toml \
    --connect-to-id icYAah8kp9L3wS5efDk5s68AzWfgNRSSWyjfzucY3MEAmeVF1obCb31eza8HSKSz8
```

(`--connect-to-id` accepts either base58 or 96-char hex — auto-detected.)

The node will:
1. Run a DHT lookup for that ID
2. Dial the resulting `channel_addr` (TCP)
3. Run the Liun channel handshake
4. On success, refresh the DHT routing table with the verified peer

## What survives a comp-crypto break, what doesn't

| Layer | Survives break? | Why |
|---|---|---|
| UDP/TCP transport | ✓ | No crypto in TCP/UDP themselves |
| DHT routing (XOR distance) | ✓ | Pure arithmetic |
| DHT entries (unauthenticated hints) | ✓ | No signatures used |
| Source address from observed UDP | ✓ | Not based on any crypto claim |
| Liun handshake validation | ✓ | Uses Wegman-Carter MAC (ITS) |
| Liu key exchange | ✓ | Gaussian noise + Toeplitz PA (ITS, LHL) |
| TLS / DNSSEC / signatures | ✗ | All computational |
| ECDH / Diffie-Hellman | ✗ | Computational |

**Net effect**: in a post-comp-crypto world, an adversary with full wire
visibility can:
- Read every DHT message in plaintext (it was never confidential anyway)
- Inject fake DHT entries (worst case: sends you to a wrong address; the
  Liun handshake fails and you retry)
- DoS the discovery layer (annoyance, doesn't break security)

What they **cannot** do:
- Forge a valid Liun handshake (no shared keys)
- Decrypt past or future Liun channel traffic (ITS, perfect secrecy)
- Impersonate a peer to trick you into a fake channel (no MAC keys = no
  valid messages)

## Limitations and future work

- **NAT traversal**: not implemented. Nodes need public IPs or port forwarding.
  UPnP / STUN-like mechanisms would help but require care to not introduce
  centralization or computational dependencies.
- **Sybil resistance in DHT**: standard Kademlia is vulnerable to Sybil
  attacks on the routing layer (eclipse). Mitigated by `liun-overlay::trust`
  (PageRank-based trust graph at a higher layer), but the DHT layer itself
  doesn't enforce it.
- **Local discovery (mDNS)**: not implemented. Useful for LAN setups; small
  feature add.
- **DHT-based peer introduction**: peers discover each other via DHT
  and establish trust through auto-trust pipeline bursts (real Liun
  handshake, randomized timing). No separate introduction protocol.
- **Eviction policies**: bucket-full case currently rejects new contacts
  rather than ping-evicting the oldest. Functional but not strictly Kademlia-spec.
