# Deployment

Recipes for running `liun-node` as a persistent service, and `chat` / `relay`
when you want to run them long-term.

For adversary assumptions and what this binary does/doesn't protect against,
read [`THREAT_MODEL.md`](THREAT_MODEL.md) first. For the supply-chain
discipline and process-hardening details, see [`SECURITY.md`](SECURITY.md).
For wire format details, see [`PROTOCOL.md`](PROTOCOL.md).

## One-command host setup (systemd)

```bash
# 1. Install the binary
sudo cp target/x86_64-unknown-linux-musl/release/liun-node /usr/local/bin/
sudo chmod +x /usr/local/bin/liun-node

# 2. Make a service user and state dir
sudo useradd --system --no-create-home --shell /usr/sbin/nologin liun
sudo mkdir -p /var/lib/liun /etc/liun
sudo chown liun:liun /var/lib/liun /etc/liun

# 3. Generate identity + config (interactive or with --defaults)
sudo -u liun /usr/local/bin/liun-node --data-dir /var/lib/liun init --defaults

# 4. Copy the generated config to /etc/liun so the service can read it
sudo cp /var/lib/liun/config.toml /etc/liun/config.toml

# 5. Install and enable the systemd unit
sudo cp deploy/liun-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now liun-node

# 6. Watch it
systemctl status liun-node
journalctl -u liun-node -f
curl http://127.0.0.1:9090/health
```

The unit file enables:
- `--rng auto` (detects best ITS source: RDSEED → RNDR → trandom → urandom)
- `--admin-listen 127.0.0.1:9090` for /health and /metrics (loopback-only)
- `TimeoutStopSec=10` graceful shutdown with SIGTERM, forced kill after 10s
- Comprehensive systemd hardening (NoNewPrivileges, ProtectSystem, RestrictSUIDSGID, MemorySwapMax=0 to prevent key material from hitting swap, AmbientCapabilities=CAP_IPC_LOCK so the process can mlock pages if it chooses)

## Process hardening flags

`liun-node` and `chat` apply process-level hardening at startup. These are
on by default; you can toggle them via CLI:

- **Core dumps + ptrace attach** disabled by default via
  `prctl(PR_SET_DUMPABLE, 0)`. Pass `--debug-allow-core-dumps` to opt
  back in for debugging. In production leave default.
- **Memory locking** (prevents swap of key material) is opt-in via
  `--mlock-memory`. Requires `CAP_IPC_LOCK` (the systemd unit grants
  it). If the capability is missing, the node logs a warning and
  continues unlocked (memory may swap if the kernel chooses).

The systemd unit in `deploy/liun-node.service` already passes sensible
defaults; the flags above are for operators running outside systemd.

## Docker / Compose

```bash
docker build -t liun-node:latest -f deploy/Dockerfile .

# First run — generate identity + config
docker run --rm \
    -v liun-data:/var/lib/liun \
    liun-node:latest \
    /usr/local/bin/liun-node --data-dir /var/lib/liun init --defaults

# Long-running
docker run -d --name liun-node \
    -p 7767:7767/udp -p 7767:7767/tcp \
    -p 127.0.0.1:9090:9090 \
    -v liun-data:/var/lib/liun \
    -v liun-etc:/etc/liun \
    liun-node:latest
```

For multi-node clusters (dev / test), `docker-compose.yml` with a small mesh
of 3 seeds is straightforward — configure `/etc/liun/config.toml` on each
with the other two as `[[dht_seeds]]`.

## Firewall

Open on every host that should be reachable:
- **UDP 7767** — DHT discovery queries
- **TCP 7767** — Liun channel handshake (inbound from peers who found you via DHT)
- Optionally **TCP 9090** on localhost-only — admin HTTP (health + metrics)

UFW example:
```bash
sudo ufw allow 7767/udp
sudo ufw allow 7767/tcp
# admin stays loopback-only — do not open
```

Cloud provider security groups: same two ports to world for public nodes;
admin port to monitoring VPC only, or leave unbound.

## Observability

**Health probe** (for load balancers, Kubernetes liveness):
```bash
curl http://127.0.0.1:9090/health
# {"status":"ok","uptime_s":42,"identity":"...","fingerprint":"138f04c7",
#  "rng":"rdseed","its":true,"dht_routing_size":12,
#  "send_pool_bytes":10063,"recv_pool_bytes":10094}
```

**Prometheus** scrape config:
```yaml
scrape_configs:
  - job_name: liun
    static_configs:
      - targets: ['liun-node-1:9090', 'liun-node-2:9090', 'liun-node-3:9090']
    metrics_path: /metrics
```

Key metrics (monotonic counters unless noted):
- `liun_uptime_seconds` (gauge)
- `liun_its` (gauge, 0 if CSPRNG, 1 if any ITS source: rdseed/rndr/trandom)
- `liun_dht_routing_size` (gauge)
- `liun_send_pool_bytes`, `liun_recv_pool_bytes` (gauges)
- `liun_dht_queries_received_total`, `liun_dht_responses_sent_total`
- `liun_chat_messages_sent_total`, `liun_chat_messages_received_total`
- `liun_chat_mac_failures_total` (alert if this rises — attempted tampering)
- `liun_liu_rounds_total`, `liun_liu_round_failures_total`
- `liun_rdseed_retries_total` (alert if climbing fast — DRNG stress)
- `liun_pool_exhausted_total` (alert on ANY growth — users are seeing paused traffic; ITS has no fallback)

## Graceful shutdown

`SIGTERM` triggers orderly shutdown:
1. Listener stops accepting new connections
2. DHT refresh task saves its routing table to `~/.liun/dht_peers.bin`
3. Background tasks exit
4. Drop-order zeroizes in-memory pools and MAC keys
5. Process exits with status 0

A second `SIGTERM` (or `SIGKILL`) within the timeout forces exit. The default
`TimeoutStopSec=10` in the systemd unit gives 10 seconds for a clean
shutdown before systemd sends SIGKILL.

## Rate limiting

Incoming DHT queries are rate-limited per source IP: 1000 queries per
10-second window (≈ 100 qps peak). Over-limit packets are dropped silently.
Under legitimate use (refresh is 1 query per 5 min per peer) this is a
two-orders-of-magnitude safety margin.

The rate-limiter map is capped at 10,000 source IPs; under a source-IP
flood, oldest entries are evicted to keep memory bounded.

## State and data

`/var/lib/liun/` contains:
- `identity.toml` — your Node ID (base58). Regenerating = new network identity.
- `config.toml` — protocol parameters + `[[dht_seeds]]` list.
- `dht_peers.bin` — persisted routing table (written every 5 min + on shutdown).
- `node.toml` — node metadata.
- `trust.bin` — trust graph edges.

**To migrate a node to a new host**: copy `/var/lib/liun/` over. The identity
+ peer cache survive the move; your peers will find you at the new IP via
normal DHT refresh.

**To wipe and restart**: remove `/var/lib/liun/` and re-init. This generates
a new identity and loses all accumulated peer state.

## Upgrading

`liun-node` stores no version-sensitive state, so upgrades are
drop-in-replace-and-restart. The DHT wire format is versioned (currently v2);
mixing v1/v2 nodes would cause decode failures but not data corruption.

```bash
sudo systemctl stop liun-node
sudo cp /path/to/new/liun-node /usr/local/bin/
sudo systemctl start liun-node
```
