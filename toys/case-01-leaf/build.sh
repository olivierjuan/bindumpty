#!/usr/bin/env bash
# Build case-01-leaf: unstripped (for ground-truth extraction) + stripped ELF.
# NFR-8: pinned compiler options. Output in build/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build

CC=${CC:-clang}

# Unstripped: same codegen, symbols retained for call-graph extraction.
$CC -O1 -fno-omit-frame-pointer -o build/toy01.sym sources/toy01.c

# Stripped: the actual target. Addresses are unchanged by strip --strip-all
# (only the symbol/string tables are removed), so ground-truth addresses from
# the .sym build remain valid for the stripped binary.
cp build/toy01.sym build/toy01
strip --strip-all build/toy01

echo "built:"
ls -l build/toy01 build/toy01.sym
file build/toy01

# Keep the ground-truth call graph's binary identity in sync (NFR-2): the
# sha256 of the stripped ELF is the function set's identity.
python3 - <<'PY'
import hashlib, json
sha = hashlib.sha256(open("build/toy01", "rb").read()).hexdigest()
p = "ground_truth/call_graph.json"
g = json.load(open(p))
g["binary"]["sha256"] = sha
json.dump(g, open(p, "w"), indent=2)
print(f"call_graph.json binary.sha256 = {sha}")
PY
