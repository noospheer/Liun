#!/usr/bin/env bash
# Show a one-line health summary for every running devnet node.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADMIN_BASE=27900

shopt -s nullglob
pidfiles=("$ROOT/pids"/node-*.pid)
if (( ${#pidfiles[@]} == 0 )); then
  echo "no nodes running. ./up.sh first."
  exit 0
fi

printf "%-8s %-7s %-8s %-11s %-10s %s\n" "node" "pid" "alive" "routing" "pool_b" "id (first 12)"
printf "%-8s %-7s %-8s %-11s %-10s %s\n" "----" "---" "-----" "-------" "------" "--------------"
for pf in "${pidfiles[@]}"; do
  name=$(basename "$pf" .pid)
  idx="${name#node-}"
  pid=$(cat "$pf" 2>/dev/null || echo "?")
  alive="dead"
  if [[ -n "$pid" && "$pid" != "?" ]] && kill -0 "$pid" 2>/dev/null; then
    alive="yes"
  fi
  admin=$((ADMIN_BASE + idx))
  health=$(curl -fsS --max-time 1 "http://127.0.0.1:$admin/health" 2>/dev/null || echo "")
  if [[ -n "$health" ]]; then
    routing=$(echo "$health" | grep -oE '"dht_routing_size":[0-9]+' | head -n1 | cut -d: -f2)
    pool=$(echo "$health" | grep -oE '"send_pool_bytes":[0-9]+' | head -n1 | cut -d: -f2)
    id=$(echo "$health" | grep -oE '"identity":"[A-Za-z0-9]+"' | head -n1 | cut -d'"' -f4 | cut -c1-12)
  else
    routing="-"; pool="-"; id="-"
  fi
  printf "%-8s %-7s %-8s %-11s %-10s %s\n" "$name" "$pid" "$alive" "${routing:-?}" "${pool:-?}" "${id:-?}"
done
