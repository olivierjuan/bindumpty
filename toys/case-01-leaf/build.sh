#!/usr/bin/env bash
# Build case-01-leaf: unstripped (for ground-truth extraction) + stripped ELF.
# NFR-8: pinned compiler options. Output in build/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build

CC=${CC:-clang}

# Unstripped: same codegen, symbols retained for call-graph extraction.
$CC -O1 -fno-omit-frame-pointer -o build/toy01.sym sources/toy01.c

# Shared-object variant for the M2 hybrid harness (FR-6/FR-7): the harness
# dlopens it and resolves originals by SYMBOL (dlsym) instead of by vaddr.
# The ground-truth vaddrs stay tied to build/toy01 (the M2 exit binary);
# toy01.so carries the same source built PIC. Names resolve via dlsym, so no
# address bookkeeping is needed here.
$CC -O1 -fno-omit-frame-pointer -fPIC -shared -o build/toy01.so sources/toy01_impl.c

# Stripped: the actual target. Addresses are unchanged by strip --strip-all
# (only the symbol/string tables are removed), so ground-truth addresses from
# the .sym build remain valid for the stripped binary.
cp build/toy01.sym build/toy01
strip --strip-all build/toy01

echo "built:"
ls -l build/toy01 build/toy01.sym
file build/toy01

# Keep the ground truth in sync with the just-built binary (NFR-2). The sha256
# is the function set's identity. Additionally, function *addresses* are
# re-extracted from the unstripped build: codegen changes can shift the layout
# (observed 2026-11-14: a 0x20 shift with unchanged sizes), and stale
# addresses would make trace replay and FR-7 hooking hit the wrong bytes.
python3 - <<'PY'
import hashlib, json, re, subprocess

sha = hashlib.sha256(open("build/toy01", "rb").read()).hexdigest()

# Authoritative addresses from the unstripped build (nm).
nm_out = subprocess.run(["nm", "-n", "build/toy01.sym"], capture_output=True, text=True).stdout
addrs = {}
for line in nm_out.splitlines():
    m = re.match(r"^([0-9a-f]+)\s+[A-Z]\s+(\S+)$", line)
    if m:
        addrs[m.group(2)] = int(m.group(1), 16)

# Sync addresses + sha in both ground-truth files.
for p in ("ground_truth/call_graph.json", "ground_truth/function_specs.json"):
    g = json.load(open(p))
    if "binary" in g:
        g["binary"]["sha256"] = sha
    changed = []
    for fn in g.get("functions", []):
        want = addrs.get(fn["name"])
        if want is None:
            continue
        cur = int(str(fn["address"]), 16)
        if cur != want:
            fn["address"] = f"0x{want:x}"
            changed.append(f"{fn['name']}: 0x{cur:x}->0x{want:x}")
    json.dump(g, open(p, "w"), indent=2)
    print(f"{p}: sha={sha[:12]}… " + (", ".join(changed) if changed else "addresses unchanged"))
PY
