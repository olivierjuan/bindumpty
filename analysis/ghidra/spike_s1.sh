#!/usr/bin/env bash
# S1 spike (M0): export the call graph of a binary with Ghidra headless.
#
# Deliverable: analysis/ghidra/ExportCallGraph.java (a GhidraScript) + this
# driver. Validates FR-1's ingestion path on the real tool — the script is
# what M0's `ingest` step will run in production (M0 exit criterion: call tree
# extracted, cross-checked against the source-derived ground truth).
#
# Usage:
#   analysis/ghidra/spike_s1.sh <binary> <out.json> [ghidra_root]
#
# Downloads/extracts Ghidra 12.2 to analysis/ghidra/dist on first run
# (pinned version; see PIN.txt). Requires Java 17+ (uses Java 21 here).
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$(pwd)
GHIDRA=${GHIDRA_ROOT:-$ROOT/analysis/ghidra/dist/ghidra_12.2_PUBLIC}

if [ $# -lt 2 ]; then
    echo "usage: $0 <binary> <out.json> [ghidra_root]" >&2
    exit 2
fi
BIN=$1
OUT=$2
[ $# -ge 3 ] && GHIDRA=$3

command -v java >/dev/null || { echo "need java" >&2; exit 3; }

# First run: fetch + extract the pinned Ghidra build.
if [ ! -x "$GHIDRA/support/analyzeHeadless" ]; then
    echo "[s1] fetching pinned Ghidra (analysis/ghidra/PIN.txt)..." >&2
    . "$ROOT/analysis/ghidra/fetch.sh" "$GHIDRA"
fi

mkdir -p "$(dirname "$OUT")"
PROJ="$ROOT/analysis/ghidra/.proj"
rm -rf "$PROJ"

# Import + run the export script. -postScript runs AFTER analysis completes.
"$GHIDRA/support/analyzeHeadless" "$PROJ" fuz -import "$BIN" \
    -overwrite \
    -scriptPath "$ROOT/analysis/ghidra" \
    -postScript ExportCallGraph.java "$OUT" \
    -deleteProject 2>&1 | grep -vE "^\s*$" | tail -20

echo "[s1] wrote $OUT"
