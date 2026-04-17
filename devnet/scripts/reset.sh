#!/usr/bin/env bash
# Wipe all devnet state (identities, pools, configs, logs, pids).
# Use before bringing up a fresh devnet.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -d "$ROOT/pids" ]] && ls "$ROOT/pids"/node-*.pid >/dev/null 2>&1; then
  "$ROOT/scripts/down.sh" || true
fi

rm -rf "$ROOT/node-"* "$ROOT/logs" "$ROOT/pids"
echo "  devnet wiped"
