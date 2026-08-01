#!/usr/bin/env bash
# run_end_to_end.sh
#
# Runs all MLS-SRTP benchmarks, copies Criterion results into the
# locations the Jupyter notebook expects, and executes the notebook to
# generate all figures.
#
# Benchmarks -> figures/tables (in notebook presentation order; see
# figures_from_benches.ipynb):
#   1.  srtp_throughput              -> Figures 1-2, Tables 1-2
#   2.  replay_protection            -> Table 1
#   3.  pep_throughput               -> Figures 3-4
#   4.  rekey                        -> Figure 5
#   5.  rekey_breakdown              -> Figure 6
#   6.  key_derivation               -> Table 3
#   7.  memory_usage (binary)        -> Figure 7
#   8.  srtp_rtcp_interleaving       -> Figure 8
#   9.  granularity_throughput_ideal -> Figures 9-10
#  10.  realistic_receiver --sweep   -> Figures 11-17
#
# Usage:
#   ./run_end_to_end.sh              # run everything
#   ./run_end_to_end.sh --skip-bench # skip benchmarks, just re-run notebook

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
# run from the repo root so the cargo invocations below find the workspace
# no matter where the script is called from
cd "$REPO_ROOT"
CRITERION_SRC="$REPO_ROOT/target/criterion"
CRITERION_DST="$REPO_ROOT/crates/mls-srtp-core/benches/results/criterion"
NOTEBOOK="$REPO_ROOT/figures_from_benches.ipynb"

SKIP_BENCH=false
for arg in "$@"; do
    case "$arg" in
        --skip-bench) SKIP_BENCH=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ──- Colors for status messages ──────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# ═════════════════════════════════════════════════════════════════════
# 1. Running the benchmarks
# ═════════════════════════════════════════════════════════════════════

if [ "$SKIP_BENCH" = false ]; then

    info "Running SRTP throughput benchmark (protect + unprotect)..."
    cargo bench --package mls-srtp-core --bench srtp_throughput
    ok "SRTP throughput benchmark complete."

    info "Running replay protection benchmark..."
    cargo bench --package mls-srtp-core --bench replay_protection
    ok "Replay protection benchmark complete."

    info "Running PEP throughput benchmark (CTR + CTR_CMAC-64)..."
    cargo bench --package mls-srtp-core --bench pep_throughput
    ok "PEP throughput benchmark complete."

    info "Running MLS rekey benchmark..."
    cargo bench --package mls-srtp-core --bench rekey
    ok "MLS rekey benchmark complete."

    info "Running MLS rekey breakdown benchmark..."
    cargo bench --package mls-srtp-core --bench rekey_breakdown
    ok "MLS rekey breakdown benchmark complete."

    info "Running key derivation benchmark..."
    cargo bench --package mls-srtp-core --bench key_derivation
    ok "Key derivation benchmark complete."

    info "Running memory usage measurement..."
    (cd "$REPO_ROOT" && cargo run --release -p mls-srtp-core --bin memory_usage)
    ok "Memory usage measurement complete."

    info "Running SRTP/RTCP interleaving benchmark..."
    cargo bench --package mls-srtp-core --bench srtp_rtcp_interleaving
    ok "SRTP/RTCP interleaving benchmark complete."

    info "Running granularity throughput benchmark (ideal in-order delivery)..."
    cargo bench --package mls-srtp-core --bench granularity_throughput_ideal
    ok "Granularity throughput benchmark complete."

    info "Running realistic receiver sweep..."
    cargo bench --package mls-srtp-core --bench realistic_receiver -- --sweep
    ok "Realistic receiver sweep complete."

fi

# ═════════════════════════════════════════════════════════════════════
# 2. Copying all Criterion results to where the notebook expects them
#    (memory_usage and realistic_receiver write into benches/results/
#    directly, so they need no copy step)
#
#    Skipped with --skip-bench: without fresh benchmark runs, copying
#    would overwrite the checked-in results with whatever stale data
#    happens to sit in target/criterion.
# ═════════════════════════════════════════════════════════════════════

if [ "$SKIP_BENCH" = false ]; then

info "Copying Criterion results..."

# SRTP throughput: protect/ and unprotect/ subdirectories
rm -rf "$CRITERION_DST/srtp_throughput"
cp -r "$CRITERION_SRC/srtp_throughput" "$CRITERION_DST/srtp_throughput"

# MLS rekey: sender_rekey_pipeline/ and receiver_rekey_pipeline/ subdirectories
rm -rf "$CRITERION_DST/rekey"
mkdir -p "$CRITERION_DST/rekey"
cp -r "$CRITERION_SRC/sender_rekey_pipeline"   "$CRITERION_DST/rekey/"
cp -r "$CRITERION_SRC/receiver_rekey_pipeline"  "$CRITERION_DST/rekey/"

# MLS rekey breakdown: component measurements for stacked bar chart
rm -rf "$CRITERION_DST/rekey_breakdown"
mkdir -p "$CRITERION_DST/rekey_breakdown"
for component in breakdown_sender_propose breakdown_sender_build breakdown_sender_build_and_stage breakdown_sender_merge_pending \
                 breakdown_receiver_unprotect breakdown_receiver_verify_stage breakdown_receiver_merge_staged; do
    if [ -d "$CRITERION_SRC/$component" ]; then
        cp -r "$CRITERION_SRC/$component" "$CRITERION_DST/rekey_breakdown/"
    fi
done

# Key derivation: mls_key_export, srtp_kdf, full_key_derivation
rm -rf "$CRITERION_DST/key_derivation"
mkdir -p "$CRITERION_DST/key_derivation"
cp -r "$CRITERION_SRC/mls_key_export"       "$CRITERION_DST/key_derivation/"
cp -r "$CRITERION_SRC/srtp_kdf"             "$CRITERION_DST/key_derivation/"
cp -r "$CRITERION_SRC/full_key_derivation"  "$CRITERION_DST/key_derivation/"

# PEP throughput: ctr_encrypt/, ctr_decrypt/, ctr_cmac64_encrypt/, ctr_cmac64_decrypt/
rm -rf "$CRITERION_DST/pep_throughput"
cp -r "$CRITERION_SRC/pep_throughput" "$CRITERION_DST/pep_throughput"

# SRTP/RTCP interleaving
rm -rf "$CRITERION_DST/srtp_rtcp_interleaving"
cp -r "$CRITERION_SRC/srtp_rtcp_interleaving" "$CRITERION_DST/srtp_rtcp_interleaving"

# Granularity throughput (ideal): protect and unprotect groups
for group in granularity_protect granularity_unprotect; do
    rm -rf "$CRITERION_DST/$group"
    cp -r "$CRITERION_SRC/$group" "$CRITERION_DST/$group"
done

# Replay protection
rm -rf "$CRITERION_DST/srtp_replay_protection"
cp -r "$CRITERION_SRC/srtp_replay_protection" "$CRITERION_DST/srtp_replay_protection"

ok "Criterion results copied."

fi

# ═════════════════════════════════════════════════════════════════════
# 3. Execute the notebook to regenerate figures
# ═════════════════════════════════════════════════════════════════════

info "Executing notebook to regenerate figures..."

if command -v jupyter &>/dev/null; then
    jupyter nbconvert --to notebook --execute --inplace "$NOTEBOOK"
elif python3 -c "import nbconvert" &>/dev/null; then
    python3 -m nbconvert --to notebook --execute --inplace "$NOTEBOOK"
else
    warn "nbconvert not available. Installing jupyter and nbconvert..."
    pip3 install --quiet jupyter nbconvert ipykernel
    python3 -m nbconvert --to notebook --execute --inplace "$NOTEBOOK"
fi

ok "Notebook executed. Figures regenerated in figures/."

# ═════════════════════════════════════════════════════════════════════
# Done
# ═════════════════════════════════════════════════════════════════════

echo ""
info "All benchmarks are done and the figures are generated."
info "Output files:"
ls -la "$REPO_ROOT/figures/"*.pdf "$REPO_ROOT/figures/"*.png 2>/dev/null | while read -r line; do
    echo "        $line"
done
