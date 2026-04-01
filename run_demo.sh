#!/usr/bin/env bash
#
# MLS-SRTP Demo: launches all 4 services and runs the full pipeline.
#
#   1. Authentication Service (AS)   - port 8001
#   2. Delivery Service (DS)         - port 8080
#   3. Alice (MLS creator/SRTP multicast sender)
#   4. Bob  (MLS joiner/SRTP receiver)
#
# Usage: ./run_demo.sh

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

# -- Building everything first ------------------------------------------------
echo "=== Building all binaries ==="
cargo build -p auth-service -p client-alice -p client-bob 2>&1
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

# -- Starting Alice -----------------------------------------------------------
cargo run -p client-alice &
ALICE_PID=$!
PIDS+=($ALICE_PID)
sleep 2

# -- Starting Bob -------------------------------------------------------------
cargo run -p client-bob
BOB_EXIT=$?

# -- Waiting for Alice to finish ----------------------------------------------
wait $ALICE_PID 2>/dev/null
ALICE_EXIT=$?

echo ""
echo "========================================="
if [ "$ALICE_EXIT" -eq 0 ] && [ "$BOB_EXIT" -eq 0 ]; then
    echo "  Demo completed successfully!"
else
    echo "  Demo failed (Alice=$ALICE_EXIT, Bob=$BOB_EXIT)"
fi
echo "========================================="
