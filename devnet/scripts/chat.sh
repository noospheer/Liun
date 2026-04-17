#!/usr/bin/env bash
# Open an ITS chat between two devnet nodes. Runs `chat listen` on one
# and `chat connect` on the other; wires them via a random session id.
# This uses the standalone `chat` binary — it doesn't go through
# `liun-node`'s channel manager. Useful for quick manual test runs.
#
#   ./chat.sh 0 1         # node-0 listens, node-1 connects
set -euo pipefail

A="${1:?usage: ./chat.sh <listener-idx> <connector-idx>}"
B="${2:?usage: ./chat.sh <listener-idx> <connector-idx>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

CHAT_BASE=37700
port_a=$((CHAT_BASE + A))
sid=$(head -c 8 /dev/urandom | xxd -p)

if [[ ! -f "$REPO/relays.toml" ]]; then
  echo "  creating a throwaway relays.toml (3 local relays needed)"
  echo "  (skip this step once you have a permanent relays.toml for your setup)"
fi

echo "  listener: node-$A port=$port_a session_id=$sid"
echo "  connector: node-$B will dial 127.0.0.1:$port_a"
echo ""
echo "  Two terminals expected. Run these manually:"
echo ""
echo "    # terminal 1:"
echo "    $REPO/target/release/chat listen  127.0.0.1:$port_a \\"
echo "        --session-id $sid --relays $REPO/relays.toml"
echo ""
echo "    # terminal 2:"
echo "    $REPO/target/release/chat connect 127.0.0.1:$port_a \\"
echo "        --session-id $sid --relays $REPO/relays.toml"
