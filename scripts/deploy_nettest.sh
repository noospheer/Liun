#!/usr/bin/env bash
# deploy_nettest.sh — multi-host nettest runner.
#
# Builds the liun-node musl binary locally, ships it to N hosts, runs a
# coordinated nettest on each, collects the JSON logs, and runs compare-logs
# to summarize agreement/disagreement.
#
# Usage:
#   1. Edit HOSTS below with your servers (user@host:dht_port).
#   2. ./scripts/deploy_nettest.sh
#
# Assumes:
#   - Passwordless SSH to each host (or your agent has the keys loaded).
#   - The DHT/channel port is open in each host's firewall.
#   - Hosts have x86_64 Linux (musl binary should run anywhere).

set -euo pipefail

# ── Configure your hosts here ─────────────────────────────────────────
# Format: "user@host:port"  (port is both the TCP channel and UDP DHT port)
HOSTS=(
  "root@vps1.example.com:7767"
  "root@vps2.example.com:7767"
  "root@vps3.example.com:7767"
)

REMOTE_DIR="/root/liun"          # where to put binary + state on each host
LOCAL_LOGS_DIR="./nettest_logs"  # where to put collected JSON logs
# ──────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/liun-node"

step() { echo; echo "── $* ──"; }
host_of() { echo "${1%%:*}" | sed 's/^[^@]*@//'; }
sshpart() { echo "${1%%:*}"; }      # user@host
port() { echo "${1##*:}"; }

step "1. Build musl binary locally"
if ! command -v cargo >/dev/null; then
  echo "cargo not in PATH; install Rust first or build the binary yourself."
  exit 1
fi
( cd "$REPO_ROOT" && cargo build --release --target x86_64-unknown-linux-musl --bin liun-node )
echo "  built: $BIN ($(du -h $BIN | cut -f1))"

step "2. Ship binary to each host + ensure remote dir"
for h in "${HOSTS[@]}"; do
  s=$(sshpart "$h")
  p=$(port "$h")
  echo "  → $s"
  ssh "$s" "mkdir -p $REMOTE_DIR"
  scp -q "$BIN" "$s:$REMOTE_DIR/liun-node"
  ssh "$s" "chmod +x $REMOTE_DIR/liun-node"
done

step "3. Init each host (creates identity + base config)"
declare -A NODE_IDS
for h in "${HOSTS[@]}"; do
  s=$(sshpart "$h")
  p=$(port "$h")
  echo "  → $s"
  # Init with --force so re-runs work; --defaults so non-interactive.
  ssh "$s" "$REMOTE_DIR/liun-node --data-dir $REMOTE_DIR/data init --defaults --force >/dev/null"
  # Read back the node ID from identity.toml.
  id=$(ssh "$s" "awk -F'\"' '/^identity/ {print \$2}' $REMOTE_DIR/data/identity.toml")
  NODE_IDS["$h"]="$id"
  echo "    id: $id"
done

step "4. Build cross-seeded config for each host (everyone seeds from everyone else)"
for h in "${HOSTS[@]}"; do
  s=$(sshpart "$h")
  p=$(port "$h")
  host=$(host_of "$h")
  cfg="/tmp/liun_${host}_config.toml"
  cat > "$cfg" <<EOF
sigma_over_p   = 2.0
batch_size     = 100000
bootstrap_peers = []
n_nodes        = ${#HOSTS[@]}

EOF
  for h2 in "${HOSTS[@]}"; do
    [[ "$h2" == "$h" ]] && continue   # don't seed yourself
    seed_host=$(host_of "$h2")
    seed_port=$(port "$h2")
    seed_id="${NODE_IDS[$h2]}"
    cat >> "$cfg" <<EOF
[[dht_seeds]]
id   = "$seed_id"
addr = "${seed_host}:${seed_port}"

EOF
  done
  scp -q "$cfg" "$s:$REMOTE_DIR/data/config.toml"
  rm "$cfg"
done

step "5. Build comma-separated target list (everyone looks up everyone else)"
ALL_IDS=""
for h in "${HOSTS[@]}"; do
  id="${NODE_IDS[$h]}"
  ALL_IDS="${ALL_IDS}${ALL_IDS:+,}$id"
done

step "6. Run nettest on each host (parallel)"
mkdir -p "$LOCAL_LOGS_DIR"
PIDS=()
for h in "${HOSTS[@]}"; do
  s=$(sshpart "$h")
  p=$(port "$h")
  host=$(host_of "$h")
  # Build target list excluding self for cleaner output (we don't need to find
  # ourselves — but it's also fine if we do).
  self_id="${NODE_IDS[$h]}"
  targets=$(echo "$ALL_IDS" | tr ',' '\n' | grep -v "^$self_id$" | tr '\n' ',' | sed 's/,$//')
  log_local="$LOCAL_LOGS_DIR/${host}.json"
  log_remote="$REMOTE_DIR/data/nettest.json"

  echo "  → $s (targets: $(echo $targets | tr ',' ' ' | wc -w))"
  (
    ssh "$s" "$REMOTE_DIR/liun-node \
        --data-dir $REMOTE_DIR/data \
        --config $REMOTE_DIR/data/config.toml \
        nettest \
            --dht-listen 0.0.0.0:$p \
            --channel-port $p \
            --targets '$targets' \
            --out $log_remote" \
        > "$LOCAL_LOGS_DIR/${host}.stdout.log" 2>&1
    scp -q "$s:$log_remote" "$log_local"
  ) &
  PIDS+=($!)
done

# Wait for all parallel jobs.
for pid in "${PIDS[@]}"; do
  wait "$pid" || echo "  (host job $pid exited non-zero)"
done

step "7. Collected logs"
ls -la "$LOCAL_LOGS_DIR"

step "8. Stdout from each host"
for h in "${HOSTS[@]}"; do
  host=$(host_of "$h")
  echo
  echo "==================== $host ===================="
  cat "$LOCAL_LOGS_DIR/${host}.stdout.log" || true
done

step "9. Compare logs"
LOG_FILES=()
for h in "${HOSTS[@]}"; do
  host=$(host_of "$h")
  LOG_FILES+=("$LOCAL_LOGS_DIR/${host}.json")
done
"$BIN" compare-logs "${LOG_FILES[@]}"
