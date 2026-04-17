#!/usr/bin/env bash
# Restart a single node in place, preserving its state dir.
# Use after `cargo build --release` to pick up new binary without
# tearing down the whole devnet.
#
#   ./restart.sh 3
set -euo pipefail

N="${1:?usage: ./restart.sh <node-index>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
BIN="$REPO/target/release/liun-node"

CHANNEL_BASE=27700
DHT_BASE=27800
ADMIN_BASE=27900

pidf="$ROOT/pids/node-$N.pid"
if [[ -f "$pidf" ]]; then
  pid=$(cat "$pidf")
  echo "  → stopping node-$N (pid $pid)"
  kill -TERM "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$pidf"
fi

dir="$ROOT/node-$N"
chan=$((CHANNEL_BASE + N))
dht=$((DHT_BASE + N))
admin=$((ADMIN_BASE + N))
log="$ROOT/logs/node-$N.log"

nohup "$BIN" \
  --data-dir "$dir" \
  --listen "127.0.0.1:$chan" \
  --dht-listen "127.0.0.1:$dht" \
  --admin-listen "127.0.0.1:$admin" \
  --config "$dir/config.toml" \
  >> "$log" 2>&1 &
echo $! > "$pidf"
echo "  node-$N restarted pid=$(cat "$pidf")"
