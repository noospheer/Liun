#!/usr/bin/env bash
# Stop all devnet nodes. Graceful SIGTERM first, SIGKILL after 5s.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
shopt -s nullglob

pidfiles=("$ROOT/pids"/node-*.pid)
if (( ${#pidfiles[@]} == 0 )); then
  echo "  no pid files found; nothing to stop"
  exit 0
fi

echo "  → SIGTERM ${#pidfiles[@]} nodes"
for pf in "${pidfiles[@]}"; do
  pid=$(cat "$pf" 2>/dev/null || true)
  [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
done

# Wait up to 5s for graceful shutdown.
for _ in 1 2 3 4 5; do
  alive=0
  for pf in "${pidfiles[@]}"; do
    pid=$(cat "$pf" 2>/dev/null || true)
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && alive=1
  done
  (( alive == 0 )) && break
  sleep 1
done

# Force-kill any stragglers.
for pf in "${pidfiles[@]}"; do
  pid=$(cat "$pf" 2>/dev/null || true)
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "  forcing node $(basename "$pf" .pid) (pid $pid)"
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$pf"
done

echo "  all stopped"
