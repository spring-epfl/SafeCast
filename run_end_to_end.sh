#!/usr/bin/env bash
# run_end_to_end.sh
#
# Runs all MLS-SRTP benchmarks, copies Criterion results into the
# locations the Jupyter notebook expects, and executes the notebook to
# generate all figures.
#
# Benchmarks:
#   1. srtp_throughput_criterion  -> Figures 1-2, Tables 1-2
#   2. pep_throughput             -> Figure 3 (SRTP vs PEP comparison)
#   3. rekey                      -> Figure 4
#   4. key_derivation             -> Table 3
#
# Usage:
#   ./run_end_to_end.sh              # run everything
#   ./run_end_to_end.sh --skip-bench # skip benchmarks, just re-run notebook

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
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
    cargo bench --package mls-srtp-core --bench srtp_throughput_criterion
    ok "SRTP throughput benchmark complete."

    info "Running PEP throughput benchmark (CTR + CTR_CMAC-64)..."
    cargo bench --package mls-srtp-core --bench pep_throughput
    ok "PEP throughput benchmark complete."

    info "Running MLS rekey benchmark (2–5000 members)..."
    cargo bench --package mls-srtp-core --bench rekey
    ok "MLS rekey benchmark complete."

    info "Running key derivation benchmark..."
    cargo bench --package mls-srtp-core --bench key_derivation
    ok "Key derivation benchmark complete."

fi

# ═════════════════════════════════════════════════════════════════════
# 2. Copying all Criterion results to where the notebook expects them
# ═════════════════════════════════════════════════════════════════════

info "Copying Criterion results..."

# SRTP throughput: protect/ and unprotect/ subdirectories
rm -rf "$CRITERION_DST/srtp_throughput"
cp -r "$CRITERION_SRC/srtp_throughput" "$CRITERION_DST/srtp_throughput"

# MLS rekey: sender_rekey_pipeline/ and receiver_rekey_pipeline/ subdirectories
rm -rf "$CRITERION_DST/rekey"
mkdir -p "$CRITERION_DST/rekey"
cp -r "$CRITERION_SRC/sender_rekey_pipeline"   "$CRITERION_DST/rekey/"
cp -r "$CRITERION_SRC/receiver_rekey_pipeline"  "$CRITERION_DST/rekey/"

# Key derivation: mls_key_export, srtp_kdf, full_key_derivation
rm -rf "$CRITERION_DST/key_derivation"
mkdir -p "$CRITERION_DST/key_derivation"
cp -r "$CRITERION_SRC/mls_key_export"       "$CRITERION_DST/key_derivation/"
cp -r "$CRITERION_SRC/srtp_kdf"             "$CRITERION_DST/key_derivation/"
cp -r "$CRITERION_SRC/full_key_derivation"  "$CRITERION_DST/key_derivation/"

# PEP throughput: ctr_encrypt/, ctr_decrypt/, ctr_cmac64_encrypt/, ctr_cmac64_decrypt/
rm -rf "$CRITERION_DST/pep_throughput"
cp -r "$CRITERION_SRC/pep_throughput" "$CRITERION_DST/pep_throughput"

ok "Criterion results copied."

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
