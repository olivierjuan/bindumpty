#!/usr/bin/env bash
# Record-replay for case-01 (M0, FR-3).
#
# Ground truth for a toy whose SOURCE is known: run the original functions
# inside the sandbox (NFR-1) on the curated valid-input set and capture the
# real I/O. Output: ground_truth/traces.jsonl (fuz.traces/1, one JSON object
# per call).
#
# For real (source-unavailable) binaries the production path is tracing/
# record_frida.py — same output format. (Note: on this host in-place Frida
# calls into the parked PIE hit an access violation; documented in
# tracing/README.md. The driver route is the M0 oracle; the Frida route is
# exercised again at M2 when hooking (FR-7) makes the in-place call
# mandatory.)
set -euo pipefail
cd "$(dirname "$0")/../../"
ROOT=$(pwd)
CASE=toys/case-01-leaf
mkdir -p "$CASE/build"

# 1. Build the stripped ELF (and .sym for ground-truth extraction).
"$CASE/build.sh" >/dev/null

# 2. Compile the driver in the sandbox (no-net, non-root, NFR-1).
#    (Host clang is the same pinned version as the sandbox image; the
#    sandbox-build step is the canonical one and is exercised by tests.)
CLANG=${CLANG:-clang}
$CLANG -O1 -I "$CASE/sources" -o "$CASE/build/trace_driver" \
    "$CASE/sources/trace_driver.c"

# 3. Manifest from the spec.
.venv/bin/python - "$CASE/ground_truth/function_specs.json" \
    > "$CASE/build/manifest.txt" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1]))
for fn in spec["functions"]:
    name = fn["name"]
    if "data" in fn["inputs"]:
        for h in fn["inputs"]["data"]:
            print(f"{name} bytes {h}")
    if "x" in fn["inputs"]:
        for x in fn["inputs"]["x"]:
            print(f"{name} u32 {x}")
PY

# 4. Record.
"$CASE/build/trace_driver" "$CASE/build/manifest.txt" \
    > "$CASE/ground_truth/traces.jsonl"

echo "recorded $(wc -l < "$CASE/ground_truth/traces.jsonl") traces -> $CASE/ground_truth/traces.jsonl"
head -3 "$CASE/ground_truth/traces.jsonl"
