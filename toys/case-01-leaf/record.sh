#!/usr/bin/env bash
# Record-replay for case-01 (M0, FR-3) via Frida — the production path.
#
#   1. build the stripped ELF (with the FUZ_HOLD parking hook),
#   2. launch frida-server,
#   3. trace the parked process: call each target function on every curated
#      input and capture the real I/O,
#   4. write the trace bundle to ground_truth/traces.jsonl.
set -euo pipefail
cd "$(dirname "$0")/../../"
ROOT=$(pwd)
CASE=toys/case-01-leaf

# 1. Build the stripped ELF (and .sym for ground-truth extraction).
"$CASE/build.sh" >/dev/null

# FRIDA_SERVER: frida-server binary matching the client (see /tmp or CI cache).
FRIDA_SERVER=${FRIDA_SERVER:-frida-server}
if ! command -v "$FRIDA_SERVER" >/dev/null 2>&1 && [ ! -x "$FRIDA_SERVER" ]; then
    echo "frida-server not found at '$FRIDA_SERVER' (set FRIDA_SERVER=...)." >&2
    exit 3
fi

# 3+4. Trace and write the bundle.
"$ROOT/.venv/bin/python" tracing/record_frida.py \
    --elf "$CASE/build/toy01" \
    --specs "$CASE/ground_truth/function_specs.json" \
    --frida-server "$FRIDA_SERVER" \
    > "$CASE/ground_truth/traces.jsonl"

echo "recorded $(wc -l < "$CASE/ground_truth/traces.jsonl") traces -> $CASE/ground_truth/traces.jsonl"
head -3 "$CASE/ground_truth/traces.jsonl"
