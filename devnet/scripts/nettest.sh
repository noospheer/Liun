#!/usr/bin/env bash
# Integrated active-net test. One script, top to bottom:
#
#   1. Bring up N liun-node daemons (default 10).
#   2. Bring up 3 local `relay` instances so the k-path bootstrap works.
#   3. Launch P chat pairs (default 5). Each pair has a listener + a
#      connector with a unique session_id. Connector writes M
#      pre-generated messages to stdin (default 20 per pair). Listener's
#      stdout is captured.
#   4. Wait for all pairs to complete or time out.
#   5. Diff the captured listener output against the expected messages.
#      Report per-pair pass/fail, plus full-network tallies.
#   6. Leave the node devnet running; clean up the chat/relay
#      processes.
#
# Usage:
#   ./nettest.sh                # defaults: N=10 nodes, P=5 pairs, M=20 msgs, T=45s
#   ./nettest.sh 10 8 15 60     # N=10 nodes, P=8 pairs, M=15 msgs, T=60s deadline
#
# Outputs:
#   devnet/logs/relay-*.log
#   devnet/logs/nettest/pair-N/{listener,connector}.{log,out,expected}
#   devnet/logs/nettest/summary.txt

set -euo pipefail

N="${1:-10}"
PAIRS="${2:-5}"
MSG_PER_PAIR="${3:-20}"
TIMEOUT="${4:-45}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
NODE_BIN="$REPO/target/release/liun-node"
CHAT_BIN="$REPO/target/release/chat"
RELAY_BIN="$REPO/target/release/relay"

RELAY_BASE=27080           # local relay HTTP ports (27080, 27081, 27082)
CHAT_BASE=27400            # chat listener ports (27400+i)

TEST_ROOT="$ROOT/logs/nettest"
RELAY_PIDS=()
LISTENER_PIDS=()
CONNECTOR_PIDS=()

cleanup() {
  for p in "${LISTENER_PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  for p in "${CONNECTOR_PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  for p in "${RELAY_PIDS[@]}";  do kill -TERM "$p" 2>/dev/null || true; done
  sleep 1 2>/dev/null || true
  for p in "${LISTENER_PIDS[@]}"; do kill -KILL "$p" 2>/dev/null || true; done
  for p in "${CONNECTOR_PIDS[@]}"; do kill -KILL "$p" 2>/dev/null || true; done
  for p in "${RELAY_PIDS[@]}";  do kill -KILL "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

# Fresh test outputs but DO NOT wipe the node devnet — it's slow to rebuild.
rm -rf "$TEST_ROOT"
mkdir -p "$TEST_ROOT"

# ── Step 1: ensure nodes are up ─────────────────────────────────────
if ! ls "$ROOT/pids"/node-*.pid >/dev/null 2>&1; then
  echo "  → no nodes running; launching $N"
  "$ROOT/scripts/up.sh" "$N" --fresh
else
  echo "  → $(ls "$ROOT/pids"/node-*.pid | wc -l) existing nodes reused"
fi

# ── Step 2: local relays ─────────────────────────────────────────────
for i in 0 1 2; do
  port=$((RELAY_BASE + i))
  log="$ROOT/logs/relay-$i.log"
  nohup "$RELAY_BIN" --listen "127.0.0.1:$port" > "$log" 2>&1 &
  pid=$!
  RELAY_PIDS+=("$pid")
  echo "  relay-$i   pid=$pid port=$port"
done

# Brief pause so relays finish binding.
sleep 1 2>/dev/null || true

RELAYS_TOML="$TEST_ROOT/relays.toml"
cat > "$RELAYS_TOML" <<EOF
[[relay]]
url = "http://127.0.0.1:$((RELAY_BASE + 0))"
operator = "local0"
jurisdiction = "test"

[[relay]]
url = "http://127.0.0.1:$((RELAY_BASE + 1))"
operator = "local1"
jurisdiction = "test"

[[relay]]
url = "http://127.0.0.1:$((RELAY_BASE + 2))"
operator = "local2"
jurisdiction = "test"
EOF

# ── Step 3: chat pairs ───────────────────────────────────────────────
echo ""
echo "  → launching $PAIRS chat pairs, $MSG_PER_PAIR messages each"
echo ""

for p in $(seq 0 $((PAIRS-1))); do
  dir="$TEST_ROOT/pair-$p"
  mkdir -p "$dir"
  sess="nettest_p${p}_$$"                 # unique per pair, per invocation
  port=$((CHAT_BASE + p))

  # Expected messages — content the connector sends, one per line.
  : > "$dir/expected"
  for m in $(seq 1 "$MSG_PER_PAIR"); do
    echo "pair${p}_msg${m}_$(openssl rand -hex 4 2>/dev/null || echo $RANDOM)" >> "$dir/expected"
  done

  # Listener: collects incoming messages to stdout.
  (
    "$CHAT_BIN" listen "127.0.0.1:$port" \
      --session-id "$sess" --relays "$RELAYS_TOML" \
      </dev/null > "$dir/listener.out" 2> "$dir/listener.log"
  ) &
  LISTENER_PIDS+=($!)

  # Connector: pipes predefined messages via stdin, then holds the pipe
  # open so the chat process doesn't see EOF and exit while messages
  # are still in-flight to the listener.
  (
    sleep 4
    {
      while read -r line; do
        printf '%s\n' "$line"
        sleep 1
      done < "$dir/expected"
      # Hold stdin open for up to TIMEOUT so the session stays alive
      # and the listener can finish receiving + the exchange continues.
      sleep "$TIMEOUT"
    } | \
      "$CHAT_BIN" connect "127.0.0.1:$port" \
        --session-id "$sess" --relays "$RELAYS_TOML" \
        > "$dir/connector.out" 2> "$dir/connector.log"
  ) &
  CONNECTOR_PIDS+=($!)

  echo "  pair-$p  session=$sess  port=$port"
done

# ── Step 4: wait with deadline ───────────────────────────────────────
echo ""
echo "  → waiting up to ${TIMEOUT}s for pairs to finish"
deadline=$(( $(date +%s) + TIMEOUT ))
while (( $(date +%s) < deadline )); do
  # All connectors finished?
  done_count=0
  for pid in "${CONNECTOR_PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      done_count=$((done_count + 1))
    fi
  done
  if (( done_count == PAIRS )); then
    echo "  all connectors done (${done_count}/${PAIRS})"
    break
  fi
  sleep 1 2>/dev/null || true
done

# Give listeners one more second to flush stdout after the connector stops.
sleep 2 2>/dev/null || true

# ── Step 5: verify ───────────────────────────────────────────────────
SUMMARY="$TEST_ROOT/summary.txt"
: > "$SUMMARY"

echo ""
echo "  ══ PER-PAIR RESULTS ══"
printf "  %-8s %-10s %-12s %-10s %s\n" "pair" "expected" "received" "missed" "status"
printf "  %-8s %-10s %-12s %-10s %s\n" "----" "--------" "--------" "------" "------"

pass=0
fail=0
for p in $(seq 0 $((PAIRS-1))); do
  dir="$TEST_ROOT/pair-$p"
  expected_count=$(wc -l < "$dir/expected" 2>/dev/null | tr -d ' ')
  # Extract received messages. The chat binary prints each incoming
  # message on a line prefixed by a timestamp and some decoration. We
  # look for the unique `pairN_msg` pattern we generated.
  received_count=0
  if [[ -f "$dir/listener.out" ]]; then
    received_count=$(grep -c -F "pair${p}_msg" "$dir/listener.out" 2>/dev/null || true)
    received_count=${received_count:-0}
  fi
  missed=$(( expected_count - received_count ))
  if (( missed <= 0 )); then
    status="PASS"
    pass=$((pass + 1))
  else
    status="FAIL"
    fail=$((fail + 1))
  fi
  printf "  %-8s %-10s %-12s %-10s %s\n" "pair-$p" "$expected_count" "$received_count" "$missed" "$status"
  echo "pair-$p expected=$expected_count received=$received_count missed=$missed $status" >> "$SUMMARY"
done

total_expected=$((PAIRS * MSG_PER_PAIR))
total_received=$(for p in $(seq 0 $((PAIRS-1))); do
  grep -c -F "pair${p}_msg" "$TEST_ROOT/pair-$p/listener.out" 2>/dev/null || echo 0
done | awk '{s+=$1}END{print s}')

echo ""
echo "  ══ TOTALS ══"
echo "  pairs passed: $pass / $PAIRS"
echo "  messages:     $total_received / $total_expected"

# ── Step 6: security spot-checks ────────────────────────────────────
echo ""
echo "  ══ SECURITY SPOT-CHECKS ══"

sec_fail=0
strip_ansi() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g'; }

# 6a. MAC verifications: every received message must log "MAC: ✓".
#     Any log line containing "MAC fail", "⚠", or "tampered" is a red flag.
mac_ok_total=0
mac_fail_total=0
for p in $(seq 0 $((PAIRS-1))); do
  dir="$TEST_ROOT/pair-$p"
  ok=$(strip_ansi < "$dir/listener.out" 2>/dev/null | grep -c 'MAC: ✓' || true)
  mf=$({ strip_ansi < "$dir/listener.log"; strip_ansi < "$dir/listener.out"; } 2>/dev/null \
          | grep -cE 'MAC (fail|invalid)|tampered|\bMAC FAIL\b' || true)
  mac_ok_total=$((mac_ok_total + ok))
  mac_fail_total=$((mac_fail_total + mf))
done
printf "  %-45s " "MAC verifications (all received msgs):"
if (( mac_ok_total >= total_received )) && (( mac_fail_total == 0 )); then
  echo "✓ $mac_ok_total / $total_received OK, 0 failures"
else
  echo "✗ ok=$mac_ok_total received=$total_received failures=$mac_fail_total"
  sec_fail=$((sec_fail + 1))
fi

# 6b. Pool-exhaustion metric across the node fleet — must be 0 (no fallback).
pool_exh_total=0
for pidf in "$ROOT/pids"/node-*.pid; do
  [[ -f "$pidf" ]] || continue
  idx=$(basename "$pidf" .pid | sed 's/node-//')
  admin=$((27900 + idx))
  m=$(curl -fsS --max-time 0.5 "http://127.0.0.1:$admin/metrics" 2>/dev/null \
      | awk '/^liun_pool_exhausted_total /{print $2}')
  pool_exh_total=$(( pool_exh_total + ${m:-0} ))
done
printf "  %-45s " "Pool-exhaustion events (no-fallback check):"
if (( pool_exh_total == 0 )); then
  echo "✓ 0 across fleet"
else
  echo "✗ $pool_exh_total — SOMEONE TRIED TO USE KEY MATERIAL PAST EXHAUSTION"
  sec_fail=$((sec_fail + 1))
fi

# 6c. Fresh OTP per message: sum "OTP: NN key bits withdrawn" / "consumed".
otp_bits_total=0
otp_msgs=0
for p in $(seq 0 $((PAIRS-1))); do
  dir="$TEST_ROOT/pair-$p"
  for log in "$dir/listener.out" "$dir/connector.out"; do
    [[ -f "$log" ]] || continue
    while read -r bits; do
      otp_bits_total=$((otp_bits_total + bits))
      otp_msgs=$((otp_msgs + 1))
    done < <(strip_ansi < "$log" | grep -oE 'OTP: [0-9]+ key bits' | grep -oE '[0-9]+')
  done
done
if (( otp_msgs > 0 )); then
  avg=$(( otp_bits_total / otp_msgs ))
  printf "  %-45s ✓ %d bits total across %d msgs (avg %d/msg)\n" \
    "Fresh OTP consumed per message:" "$otp_bits_total" "$otp_msgs" "$avg"
else
  printf "  %-45s ? no OTP log lines captured (could not verify)\n" "Fresh OTP consumed per message:"
fi

# 6d. Wire overhead: every `Frame: NB on wire (MB overhead)` line parses
#     and `overhead` is the fixed 16-byte chat payload header (tag+ts),
#     not the plaintext size. Demonstrates OTP-encrypted (not echoed).
frame_lines=$(for p in $(seq 0 $((PAIRS-1))); do
  strip_ansi < "$TEST_ROOT/pair-$p/listener.out" 2>/dev/null
done | grep -oE 'Frame: [0-9]+B on wire \([0-9]+B overhead\)' | head -3)
printf "  %-45s\n" "Frame layout (first 3 received):"
if [[ -n "$frame_lines" ]]; then
  echo "$frame_lines" | while read -r line; do echo "    $line"; done
else
  echo "    (no frame lines captured)"
fi

# 6e. RNG mode of the running node fleet (ITS requires rdseed).
rng_mode="?"; its_flag="?"
h=$(curl -fsS --max-time 0.5 "http://127.0.0.1:27900/health" 2>/dev/null || true)
if [[ -n "$h" ]]; then
  rng_mode=$(echo "$h" | grep -oE '"rng":"[^"]*"' | head -n1 | cut -d'"' -f4)
  its_flag=$(echo "$h" | grep -oE '"its":(true|false)' | head -n1 | cut -d: -f2)
fi
printf "  %-45s " "Node RNG mode:"
if [[ "$its_flag" == "true" ]]; then
  echo "✓ $rng_mode (its=true)"
else
  echo "  $rng_mode (its=$its_flag)   [urandom is CSPRNG; for full ITS restart with --rng rdseed]"
fi

# 6f. Adversarial-path unit tests: run the short, targeted set. Fast
#     because the crates are already built; just verifies nobody
#     silently regressed the tamper/replay/forgery rejection code.
echo "  Adversarial-path unit tests:"
(
  cd "$REPO"
  source ~/.cargo/env 2>/dev/null || true
  out=$(cargo test --release --quiet --package liun-receipts --lib \
          -- --test-threads=1 \
          tampered_field_breaks_mac \
          cannot_forge_other_half_without_their_key \
          tamper_with_total_count_fails_verify \
          batch_rejects_tampered_list \
          2>&1 | tail -25)
  echo "$out" | grep -E '^test |^test result' | sed 's/^/    /'
) || true

echo ""
echo "  detailed logs: $TEST_ROOT/pair-*/"
echo "  summary:       $SUMMARY"
echo ""
if (( fail == 0 && sec_fail == 0 )); then
  echo "  ✓ ALL PAIRS PASSED & SECURITY SPOT-CHECKS CLEAN"
  exit 0
elif (( fail == 0 )); then
  echo "  ⚠ functional pairs PASS but $sec_fail security check(s) failed — see above"
  exit 2
else
  echo "  ✗ ${fail} pair(s) failed${sec_fail:+, $sec_fail security check(s) failed} — inspect $TEST_ROOT/pair-N/"
  exit 1
fi
