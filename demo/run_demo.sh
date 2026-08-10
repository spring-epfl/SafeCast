#!/usr/bin/env bash
#
# MLS-SRTP Demo: launches all services and runs the full pipeline.
#
#   1. Authentication Service (AS)   - port 8001
#   2. Delivery Service (DS)         - port 8080
#   3. Creator                       - creates the MLS group, delivers Welcome
#   4. Sender (joiner)               - joins MLS group, sends SRTP
#   5. Receiver(s) (joiners)         - join MLS group, receive SRTP
#
# Usage:
#   ./demo/run_demo.sh      # default: 1 sender + 1 receiver
#   ./demo/run_demo.sh 3    # 1 sender + 3 receivers

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIDS=()

cleanup() {
    echo ""
    echo "Shutting down services..."
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

# Polls until something is listening on 127.0.0.1:$port (10 s timeout). The
# clients' first HTTP call panics on connection refused instead of retrying,
# so the AS/DS must be bound before any client starts.
wait_for_port() {
    local port="$1" name="$2"
    for _ in $(seq 1 50); do
        if (echo >"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: $name is not listening on port $port after 10s" >&2
    exit 1
}

# -- Parsing arguments ---------------------------------------------------------
NUM_RECEIVERS="${1:-1}"

echo "=== MLS-SRTP Demo ==="
echo "Sender: 1 (auto-named)"
echo "Receivers: $NUM_RECEIVERS (auto-named)"
echo ""

# -- Building everything first ------------------------------------------------
echo "=== Building all binaries ==="
cargo build -p auth-service -p safecast-client 2>&1
(cd "$ROOT/third_party/openmls" && cargo build -p mls-ds 2>&1)
echo ""

# -- Starting AS --------------------------------------------------------------
cargo run -p auth-service &
PIDS+=($!)
wait_for_port 8001 "Authentication Service"

# -- Starting DS (of OpenMLS) -------------------------------------------------
(cd "$ROOT/third_party/openmls" && cargo run -p mls-ds) &
PIDS+=($!)
wait_for_port 8080 "Delivery Service"

# -- Starting creator (sets up the MLS group, delivers Welcome) ----------------
cargo run -p safecast-client -- --mode creator --senders 1 --receivers "$NUM_RECEIVERS" &
PIDS+=($!)
sleep 1

# -- Starting receivers (joiners) in background -------------------------------
RECEIVER_PIDS=()
for i in $(seq 1 "$NUM_RECEIVERS"); do
    cargo run -p safecast-client -- --mode receiver &
    pid=$!
    PIDS+=($pid)
    RECEIVER_PIDS+=($pid)
done
sleep 2

# -- Starting sender (joiner) -------------------------------------------------
SENDER_EXIT=0
cargo run -p safecast-client -- --mode sender || SENDER_EXIT=$?

# -- Waiting for receivers to finish ------------------------------------------
RECEIVER_EXIT=0
for pid in ${RECEIVER_PIDS[@]+"${RECEIVER_PIDS[@]}"}; do
    wait "$pid" 2>/dev/null || RECEIVER_EXIT=1
done

echo ""
echo "========================================="
if [ "$SENDER_EXIT" -eq 0 ] && [ "$RECEIVER_EXIT" -eq 0 ]; then
    echo "  Demo completed successfully!"
    DEMO_EXIT=0
else
    echo "  Demo failed (sender=$SENDER_EXIT, receivers=$RECEIVER_EXIT)"
    DEMO_EXIT=1
fi
echo "========================================="
exit "$DEMO_EXIT"
