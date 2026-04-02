#!/usr/bin/env bash
#
# MLS-SRTP Demo: launches all services and runs the full pipeline.
#
#   1. Authentication Service (AS)   - port 8001
#   2. Delivery Service (DS)         - port 8080
#   3. Sender (creator)              - creates MLS group, sends SRTP
#   4. Receiver(s) (joiners)         - join MLS group, receive SRTP
#
# Usage:
#   ./run_demo.sh           # default: 1 sender + 1 receiver
#   ./run_demo.sh 3         # 1 sender + 3 receivers

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PIDS=()

cleanup() {
    echo ""
    echo "Shutting down services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

# -- Parsing arguments ---------------------------------------------------------
NUM_RECEIVERS="${1:-1}"

echo "=== MLS-SRTP Demo ==="
echo "Sender: 1 (auto-named)"
echo "Receivers: $NUM_RECEIVERS (auto-named)"
echo ""

# -- Building everything first ------------------------------------------------
echo "=== Building all binaries ==="
cargo build -p auth-service -p mls-srtp-client 2>&1
(cd "$ROOT/openmls" && cargo build -p mls-ds 2>&1)
echo ""

# -- Starting AS --------------------------------------------------------------
cargo run -p auth-service &
PIDS+=($!)
sleep 1

# -- Starting DS (of OpenMLS) -------------------------------------------------
(cd "$ROOT/openmls" && cargo run -p mls-ds) &
PIDS+=($!)
sleep 1

# -- Starting receivers (joiners) in background -------------------------------
RECEIVER_PIDS=()
for i in $(seq 1 "$NUM_RECEIVERS"); do
    cargo run -p mls-srtp-client -- --mode receiver &
    pid=$!
    PIDS+=($pid)
    RECEIVER_PIDS+=($pid)
done
sleep 2

# -- Starting sender (creator) ------------------------------------------------
cargo run -p mls-srtp-client -- --mode sender --receivers "$NUM_RECEIVERS"
SENDER_EXIT=$?

# -- Waiting for receivers to finish ------------------------------------------
RECEIVER_EXIT=0
for pid in "${RECEIVER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || RECEIVER_EXIT=1
done

echo ""
echo "========================================="
if [ "$SENDER_EXIT" -eq 0 ] && [ "$RECEIVER_EXIT" -eq 0 ]; then
    echo "  Demo completed successfully!"
else
    echo "  Demo failed (sender=$SENDER_EXIT, receivers=$RECEIVER_EXIT)"
fi
echo "========================================="
