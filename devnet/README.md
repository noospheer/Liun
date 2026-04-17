# DevNet: local multi-node test harness

Run N `liun-node` instances on localhost for fast iteration: edit code,
rebuild, restart, observe, repeat. Each instance has its own data dir,
identity, and ports.

## Layout

```
devnet/
├── scripts/           # up / down / logs / status / restart / rebuild / chat / reset
├── node-0/            # genesis seed — first node brought up
│   ├── identity.toml
│   ├── config.toml
│   └── peers/         # pool state, DHT cache (survives restarts)
├── node-1/
├── ...
├── logs/              # node-N.log — persistent across restarts
└── pids/              # node-N.pid — used by down/restart
```

Port scheme:
- channel TCP = `27700 + N`
- DHT UDP     = `27800 + N`
- admin HTTP  = `27900 + N`

## Commands

| Script | What it does |
|---|---|
| `scripts/up.sh N` | Build (if needed) + launch N nodes. Node-0 is genesis, 1..N-1 use node-0 as DHT seed. Add `--fresh` to wipe state first. |
| `scripts/down.sh` | Graceful SIGTERM to all, SIGKILL after 5s if stuck. |
| `scripts/status.sh` | One-line per node: pid, alive, routing table size, pool bytes, identity prefix. |
| `scripts/logs.sh [N]` | Tail node N's log, or all with prefix if no arg. |
| `scripts/restart.sh N` | Stop and relaunch a single node in place, preserving data dir. |
| `scripts/rebuild.sh` | `cargo build --release` + restart every running node. |
| `scripts/reset.sh` | Shut everything down and wipe all state. |
| `scripts/chat.sh A B` | Prints the two commands for opening an ITS chat between node A (listener) and node B (connector). |
| `scripts/live.sh [INT]` | Live dashboard (uptime, routing, pool bytes, chat counters) refreshed every INT seconds. |
| `scripts/chaos.sh [N T TICK]` | Spin up N nodes + cycle through random kill/restart/probe actions for T seconds. |
| `scripts/nettest.sh [N P M T]` | Full integrated test: N nodes + 3 relays + P chat pairs, each sending M verified messages, deadline T. **Exit status reflects pass/fail.** |

## Typical iteration loop

```bash
cd devnet

# First time
scripts/up.sh 5 --fresh
scripts/status.sh

# Edit something in crates/ or src/
$EDITOR ../src/main.rs

# Pick up the change on every running node, in place
scripts/rebuild.sh

# Check nobody died
scripts/status.sh
scripts/logs.sh      # tail everything

# Done for the day
scripts/down.sh
```

## Debugging a single node

```bash
scripts/restart.sh 3   # restart just node-3 to test a theory
scripts/logs.sh 3      # watch its log
curl http://127.0.0.1:27903/health | jq
```

## Integration notes

- **State persists** between restarts (pool state, identity, DHT cache).
  Use `scripts/reset.sh` or `scripts/up.sh N --fresh` to start over.
- **Log files grow**; `scripts/rebuild.sh` appends, doesn't rotate.
  `scripts/reset.sh` truncates.
- **Ports conflict** if you run two devnets from different checkouts.
  Edit the `*_BASE` constants at the top of each script if needed.
- `scripts/rebuild.sh` takes ~15s on a warm cache, ~60s cold.

## Known behaviors

- `dht_routing_size` metric on the genesis node may stay 0 until the
  first 5-minute refresh tick — it's only updated during that task, not
  on incoming query arrival. Peers ARE in node-0's table; just the
  metric gauge hasn't been pushed yet.
- RNG defaults to `urandom` for dev speed. Pass `--rng auto` to use
  the best available ITS source (RDSEED, RNDR, or trandom).
- CPU usage is dominated by the continuous Liu exchange on active
  channels. Idle devnets (no chat sessions) are near-zero load.
