#!/usr/bin/env bash
# Rebuild release binary and restart every node. Fast iteration loop:
#
#   ... edit code ...
#   ./rebuild.sh
#
# (Equivalent to: cargo build --release && for i in ...; do ./restart.sh i; done.)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

echo "  → cargo build --release --bin liun-node"
(cd "$REPO" && cargo build --release --bin liun-node)

shopt -s nullglob
pidfiles=("$ROOT/pids"/node-*.pid)
for pf in "${pidfiles[@]}"; do
  name=$(basename "$pf" .pid)
  idx="${name#node-}"
  "$ROOT/scripts/restart.sh" "$idx"
done
