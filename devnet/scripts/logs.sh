#!/usr/bin/env bash
# Tail devnet logs.
#   ./logs.sh        # tail all nodes, prefixed by name
#   ./logs.sh 3      # tail only node-3
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $# -eq 1 ]]; then
  f="$ROOT/logs/node-$1.log"
  [[ -f "$f" ]] || { echo "no such log: $f"; exit 1; }
  tail -F "$f"
  exit 0
fi

shopt -s nullglob
logs=("$ROOT/logs"/node-*.log)
if (( ${#logs[@]} == 0 )); then
  echo "no log files found. Did you run ./up.sh?"
  exit 1
fi

# Tail all with a name prefix on each line. `multitail` would be fancier; we
# use sed for zero-dependency portability.
tail -Fn 50 "${logs[@]}" | awk '
  /^==> / { f=$2; sub(/^.*node-/, "", f); sub(/\.log <==$/, "", f); prefix=sprintf("[n%s] ", f); next }
  { printf "%s%s\n", prefix, $0 }
'
