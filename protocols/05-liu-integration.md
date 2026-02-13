# Protocol 05: Liu Protocol Integration

## Purpose

Define how Liun uses the Liu protocol (`liuproto`) as its ITS key
engine. Liu provides the core primitive: turning a finite PSK into an
unlimited stream of ITS key material.

## Role in Liun

Liu is the **engine** that powers every other protocol:

```
Protocol 01 (Bootstrap)    --> produces PSKs
Protocol 05 (THIS)         --> PSK -> ITS channel (Liu)
Protocol 02 (Peer Intro)   --> uses ITS channels to create more PSKs
Protocol 03 (Shamir DKG)   --> uses ITS channels for share distribution
Protocol 04 (USS Signing)  --> uses ITS key material for signing
```

Every ITS channel in the network is a Liu channel. Every secret
transmitted between nodes travels over a Liu-authenticated,
Liu-encrypted channel.

## Interface

Liun treats `liuproto` as a black box:

```python
from liuproto.link import NetworkServerLink, NetworkClientLink
from liuproto.endpoint import Physics

# Standard physics parameters (sigma/p = 2 recommended)
physics = Physics(
    n_exchanges=1,
    reflection_coefficient=0.8,
    cutoff=0.1,
    ramp_time=5,
    resolution=0,
    masking_time=0,
    masking_magnitude=0,
    modulus=0.2       # mod_mult -> sigma/p = 2
)

# Server side (one per channel):
server = NetworkServerLink(
    (host, port),
    pre_shared_key=psk     # From bootstrap or peer introduction
)
# Runs in a thread:
server.run_batch_signbit_nopa()

# Client side:
client = NetworkClientLink(
    (host, port),
    physics,
    pre_shared_key=psk     # Same PSK
)
result = client.run_signbit_nopa(
    B=100000,              # Bits per run (default 100k)
    n_runs=10,             # Runs per batch
    n_batches=1,           # Batches per connection
    mod_mult=0.5,          # sigma/p = 2
    n_test_rounds=2,       # Sigma verification
    rng_mode='urandom'     # 'urandom' or 'rdseed'
)
```

## Result Structure

```python
result['secure_bits']          # numpy uint8 array — the ITS key bits
result['n_secure']             # Number of secure bits generated
result['sigma_verified']       # True if sigma/p was verified
result['psk_recycled']         # True if enough output for new PSK
result['achieved_epsilon']     # Security parameter achieved
result['pool_available_bits']  # Remaining pool capacity
```

## Key Properties Used by Liun

### 1. ITS Key Expansion

A ~12.5 KB PSK produces ~1 Mbit of ITS key per batch. Continuous
batches produce unlimited key. This powers:
- ITS channel encryption (OTP from key bits)
- ITS authentication (MAC keys from key bits)
- ITS share distribution (DKG shares encrypted with key bits)

### 2. Pool Recycling (Continuous Operation)

Liu's pool recycling means a single PSK seeds infinite operation:

```
Batch 1: PSK -> 1 Mbit ITS key + recycled PSK'
Batch 2: PSK' -> 1 Mbit ITS key + recycled PSK''
Batch 3: PSK'' -> 1 Mbit ITS key + recycled PSK'''
...forever
```

Liun depends on this for:
- Channels that never expire
- Fresh key material for each epoch's DKG
- Signature polynomial re-deals

### 3. MAC Authentication

Liu's Wegman-Carter polynomial MAC over M61 authenticates every
message on every channel. Forgery probability: d/M61 ~ 5e-14 per run.

Liun inherits this authentication for:
- Share distribution integrity (DKG)
- Peer introduction integrity
- Configuration authentication

### 4. Sigma Verification

Liu verifies that sigma/p >= 2 (the channel quality parameter) via
committed chi-squared tests. This ensures the ITS security bound holds.

Liun uses this to:
- Validate channel quality before trusting key material
- Detect degraded channels (hardware failure, interference)
- Reject channels that don't meet security requirements

## PSK Lifecycle in Liun

```
1. BOOTSTRAP:  Multi-path XOR produces raw shared secret (256 bits)
                  |
2. EXPAND:     Toeplitz extractor expands to Liu PSK size (12.5 KB)
                  |
3. LIU INIT:   PSK -> first Liu batch -> ITS key material + recycled PSK
                  |
4. OPERATE:    Continuous Liu batches over ITS channel
                  |
5. RECYCLE:    Each batch produces new PSK for next batch
                  |
6. (repeat 4-5 forever)
```

The PSK is consumed once and recycled indefinitely. The initial 256-bit
bootstrap secret ultimately seeds an infinite ITS key stream.

## Channel Management

Each Liun node maintains a table of Liu channels:

```
Channel Table:
+----------+--------+--------+--------+----------+------------------+
| Peer     | Status | Port   | PSK    | Pool     | Last Batch       |
+----------+--------+--------+--------+----------+------------------+
| node_042 | active | 7767   | (ref)  | 98000    | 2026-02-12 14:30 |
| node_107 | active | 7768   | (ref)  | 95000    | 2026-02-12 14:28 |
| node_003 | idle   | 7769   | (ref)  | 100000   | 2026-02-12 13:00 |
+----------+--------+--------+--------+----------+------------------+
```

Channels are:
- **Active:** Continuous Liu batches generating key material
- **Idle:** PSK held, ready to resume on demand
- **Expired:** Node departed or channel revoked

## Performance

From Liu protocol benchmarks (see Liup/README.md Section 6.2):

| Metric | Value |
|--------|-------|
| Key generation rate (urandom) | ~2-3 Mbps per channel |
| Key generation rate (rdseed) | ~0.2 Mbps per channel |
| PSK size | ~12.5 KB per channel |
| Network overhead | ~17 bytes per key bit |

For Liun with 20 active channels per node:
- Total key generation: ~40-60 Mbps aggregate
- Total PSK storage: ~250 KB
- Sufficient for DKG, signing, and channel maintenance

## Configuration

Liun default Liu parameters:

```python
ITSNET_LIU_DEFAULTS = {
    'B': 100_000,           # Bits per run
    'n_runs': 10,           # Runs per batch
    'n_batches': 1,         # Batches per connection
    'mod_mult': 0.5,        # sigma/p = 2
    'n_test_rounds': 2,     # Sigma verification on
    'rng_mode': 'urandom',  # Default RNG mode
    'port': 7767,           # Default Liu port
}
```

These match Liu's own defaults. Liun does not modify Liu's behavior —
it only consumes its output.
