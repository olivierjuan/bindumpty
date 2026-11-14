#!/usr/bin/env bash
# toys/case-02-mem/build.sh — case-02: void-shaped parent (FR-9 memory diff).
#
# Outputs in build/ (git-ignored): the unstripped reference build, the shared
# object the hybrid harness dlopens, and the stripped binary. Ground truth:
# the function list + I/O vector JSON (toy02 ground truth is byte-vector
# based, no call graph needed beyond the leaves reused from case-01).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build

CC=${CC:-clang}

$CC -O1 -fno-omit-frame-pointer -fPIC -shared -I../case-01-leaf/sources \
    -o build/toy02.so sources/toy02_impl.c
$CC -O1 -fno-omit-frame-pointer -fPIC -shared -I../case-01-leaf/sources \
    -o build/toy02.so sources/toy02_impl.c

python3 - <<'PY'
import hashlib, json, subprocess

sha = hashlib.sha256(open("build/toy02.so", "rb").read()).hexdigest()

# ground truth: byte vectors from the reference (unstripped) build, computed
# here via ctypes on build/toy02.sym — the source IS the oracle pre-strip.
import ctypes
lib = ctypes.CDLL("./build/toy02.so")
lib.fill_keystream.restype = None
lib.fill_keystream.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_char_p, ctypes.c_size_t]
vectors = []
for seed_hex, n in [("", 0), ("00", 8), ("deadbeef", 16), ("a5a5", 33)]:
    seed = bytes.fromhex(seed_hex) if seed_hex else b""
    out = ctypes.create_string_buffer(n + 1)
    lib.fill_keystream(seed, len(seed), out, n)
    vectors.append({"seed": seed_hex, "len": n,
                    "expected_hex": out.raw[: n + 1].hex()})

doc = {
    "format": "fuz.call-graph/1",
    "binary": {"sha256": sha, "arch": "x86-64", "kind": "elf",
               "is_pie": None, "is_stripped": False,
               "source_lang": "c", "backend": "build-script"},
    "functions": [
        {"name": "fill_keystream", "address": "0x0", "size": 0,
         "demangled_sig": "void fill_keystream(const unsigned char *, unsigned long, unsigned char *, unsigned long)",
         "has_rtti": False, "is_library": False},
        {"name": "fnv1a", "address": "0x0", "size": 0, "demangled_sig": None,
         "has_rtti": False, "is_library": False, "reused_from": "case-01"},
        {"name": "digit_sum_u32", "address": "0x0", "size": 0,
         "demangled_sig": None, "has_rtti": False, "is_library": False,
         "reused_from": "case-01"},
    ],
    "edges": [
        {"caller": "fill_keystream", "callee": "fnv1a", "kind": "direct"},
        {"caller": "fill_keystream", "callee": "digit_sum_u32", "kind": "direct"},
    ],
    "topological_order": ["fnv1a", "digit_sum_u32", "fill_keystream"],
    "sccs": [],
    # FR-9 validation vectors: (seed, len) -> the exact bytes the function
    # must write (including the trailing parity byte).
    "io_vectors": vectors,
}
json.dump(doc, open("ground_truth_call_graph.json", "w"), indent=2)
print(f"toy02 ground truth: sha={sha[:12]}... {len(vectors)} IO vectors")
PY
ls -l build/