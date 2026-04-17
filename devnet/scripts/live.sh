#!/usr/bin/env bash
# Live stats dashboard for the devnet. Refreshes twice per second by default.
#
#   ./live.sh           # default 0.5s refresh
#   ./live.sh 1         # 1s refresh
#   ./live.sh 0.25      # 4x/sec
#
# Ctrl-C to exit.

set -euo pipefail

INTERVAL="${1:-0.5}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADMIN_BASE=27900

# ANSI helpers
CLEAR_SCREEN=$'\033[2J'
HOME_CURSOR=$'\033[H'
CLEAR_LINE=$'\033[K'
NL=$'\n'
BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'

cleanup() {
  printf '\033[?25h' # re-show cursor
  echo ""
}
trap cleanup EXIT INT TERM

# Hide cursor for the live view.
printf '\033[?25l'

draw() {
  local out
  out="${HOME_CURSOR}"

  out+="${BOLD}${CYAN}── liun-node devnet (live)${RESET}   "
  out+="${DIM}refresh ${INTERVAL}s · $(date +%H:%M:%S)${RESET}${CLEAR_LINE}${NL}${NL}"

  out+=$(printf "${BOLD}%-8s %-5s %-7s %-8s %-11s %-11s %-10s %-10s %-9s${RESET}" \
    "node" "alive" "uptime" "routing" "send_pool" "recv_pool" "chat_sent" "chat_recv" "pool_exh")
  out+="${CLEAR_LINE}${NL}"

  shopt -s nullglob
  local pidfiles=("$ROOT/pids"/node-*.pid)
  if (( ${#pidfiles[@]} == 0 )); then
    printf "%s%sno nodes running — ./up.sh first%s" "$out" "$YELLOW" "$RESET"
    return
  fi

  # Sort pid files numerically by node index (bash array sort-ish).
  IFS=$'\n' pidfiles=($(printf '%s\n' "${pidfiles[@]}" | sort -V))

  local total_sent=0 total_recv=0 total_send_pool=0 total_recv_pool=0
  local alive_count=0

  for pf in "${pidfiles[@]}"; do
    local name=$(basename "$pf" .pid)
    local idx="${name#node-}"
    local pid=$(cat "$pf" 2>/dev/null || echo "?")
    local alive_sym="${RED}dead${RESET}"
    local uptime="-" routing="-" send_pool="-" recv_pool="-"
    local chat_sent="-" chat_recv="-" pool_exh="-"

    if [[ -n "$pid" && "$pid" != "?" ]] && kill -0 "$pid" 2>/dev/null; then
      alive_sym="${GREEN}up${RESET}"
      alive_count=$(( alive_count + 1 ))
      local admin=$((ADMIN_BASE + idx))
      local metrics
      metrics=$(curl -fsS --max-time 0.3 "http://127.0.0.1:$admin/metrics" 2>/dev/null || true)
      if [[ -n "$metrics" ]]; then
        uptime=$(echo "$metrics" | awk '/^liun_uptime_seconds /{print $2}')
        routing=$(echo "$metrics" | awk '/^liun_dht_routing_size /{print $2}')
        send_pool=$(echo "$metrics" | awk '/^liun_send_pool_bytes /{print $2}')
        recv_pool=$(echo "$metrics" | awk '/^liun_recv_pool_bytes /{print $2}')
        chat_sent=$(echo "$metrics" | awk '/^liun_chat_messages_sent_total /{print $2}')
        chat_recv=$(echo "$metrics" | awk '/^liun_chat_messages_received_total /{print $2}')
        pool_exh=$(echo "$metrics" | awk '/^liun_pool_exhausted_total /{print $2}')

        total_sent=$((total_sent + ${chat_sent:-0}))
        total_recv=$((total_recv + ${chat_recv:-0}))
        total_send_pool=$((total_send_pool + ${send_pool:-0}))
        total_recv_pool=$((total_recv_pool + ${recv_pool:-0}))
      fi
    fi

    out+=$(printf "%-8s %-15b %-7s %-8s %-11s %-11s %-10s %-10s %-9s" \
      "$name" "$alive_sym" "${uptime:-?}" "${routing:-?}" \
      "${send_pool:-?}" "${recv_pool:-?}" \
      "${chat_sent:-?}" "${chat_recv:-?}" "${pool_exh:-?}")
    out+="${CLEAR_LINE}${NL}"
  done

  out+="${CLEAR_LINE}${NL}"
  out+="${BOLD}totals${RESET}  alive=${GREEN}${alive_count}${RESET}/${#pidfiles[@]}  "
  out+="chat(tx/rx)=${total_sent}/${total_recv}  "
  out+="pool(tx/rx)=${total_send_pool}/${total_recv_pool}${CLEAR_LINE}${NL}"
  out+="${DIM}ctrl-c to exit · logs: ./logs.sh · chaos: ./chaos.sh${RESET}${CLEAR_LINE}${NL}"
  # Clear any residue from previous frames
  out+=$'\033[J'

  printf '%s' "$out"
}

# First frame clears the screen; subsequent frames just reposition.
printf '%s' "$CLEAR_SCREEN"
while true; do
  draw
  sleep "$INTERVAL"
done
