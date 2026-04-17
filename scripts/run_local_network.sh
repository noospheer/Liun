#!/bin/bash
# Launch a local 10-node network with all nodes connecting to each other.
# Each node gets its own port (7770-7779) and data directory.

set -e

BINARY="./target/release/liun-node"
N_NODES=10
BASE_PORT=7770
PIDS=()

cleanup() {
    echo ""
    echo "Shutting down all nodes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    echo "All nodes stopped."
    # Clean up state dirs
    for i in $(seq 0 $((N_NODES - 1))); do
        rm -rf "/tmp/liun-local-$i"
    done
}
trap cleanup EXIT

echo "═══════════════════════════════════════════"
echo "  LAUNCHING $N_NODES-NODE LOCAL NETWORK"
echo "═══════════════════════════════════════════"
echo ""

# Build first
echo "Building release binary..."
cargo build --release 2>&1 | tail -1
echo ""

# Clean previous state
for i in $(seq 0 $((N_NODES - 1))); do
    rm -rf "/tmp/liun-local-$i"
done

# Start node 0 first (no peers)
PORT=$BASE_PORT
echo "Starting node 0 on port $PORT..."
$BINARY --data-dir "/tmp/liun-local-0" --listen "127.0.0.1:$PORT" 2>&1 | sed "s/^/[node-0] /" &
PIDS+=($!)
sleep 0.5

# Start remaining nodes, each connecting to node 0
for i in $(seq 1 $((N_NODES - 1))); do
    PORT=$((BASE_PORT + i))
    echo "Starting node $i on port $PORT, connecting to node 0..."
    $BINARY --data-dir "/tmp/liun-local-$i" --listen "127.0.0.1:$PORT" --peer "127.0.0.1:$BASE_PORT" 2>&1 | sed "s/^/[node-$i] /" &
    PIDS+=($!)
    sleep 0.2
done

echo ""
echo "All $N_NODES nodes started. Ports $BASE_PORT-$((BASE_PORT + N_NODES - 1))"
echo ""

# Let them run for a few seconds
sleep 3

# Check which are still alive
echo ""
echo "═══════════════════════════════════════════"
echo "  NODE STATUS"
echo "═══════════════════════════════════════════"
ALIVE=0
for i in $(seq 0 $((N_NODES - 1))); do
    PORT=$((BASE_PORT + i))
    PID=${PIDS[$i]}
    if kill -0 "$PID" 2>/dev/null; then
        IDENTITY=$(cat "/tmp/liun-local-$i/identity.toml" 2>/dev/null | grep identity | head -1 | cut -d'"' -f2 | head -c 8)
        echo "  Node $i (port $PORT, id=$IDENTITY): RUNNING (pid $PID)"
        ALIVE=$((ALIVE + 1))
    else
        echo "  Node $i (port $PORT): DEAD"
    fi
done

echo ""
echo "  $ALIVE / $N_NODES nodes alive"

# Check connections: how many nodes successfully connected to node 0
echo ""
echo "═══════════════════════════════════════════"
echo "  CONNECTION SUMMARY"
echo "═══════════════════════════════════════════"
CONNECTIONS=$(ss -tnp 2>/dev/null | grep -c "liun-node" || echo "0")
echo "  Active TCP connections involving liun-node: $CONNECTIONS"
echo ""

# Show listening ports
echo "  Listening ports:"
for i in $(seq 0 $((N_NODES - 1))); do
    PORT=$((BASE_PORT + i))
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        echo "    127.0.0.1:$PORT ✓"
    else
        echo "    127.0.0.1:$PORT ✗"
    fi
done

echo ""
echo "═══════════════════════════════════════════"
echo "  NETWORK TEST COMPLETE"
echo "═══════════════════════════════════════════"
