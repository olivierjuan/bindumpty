#!/usr/bin/env bash
# horses/src/build_m2.sh — build the FR-6/FR-7 hybrid harness.
#
# Modes:
#   default        : candidate parent over ORIGINAL callees, oracle = original
#                    parent (linked from horse_original.c). No hooks needed.
#   HORSE_HOOK=1   : funchook redirects the toy's REAL leaf entries to the
#                    validated candidate leaves; the original parent (oracle)
#                    then runs over VALIDATED callees.
#
# The harness dlopens the stripped toy for the originals (vaddr resolution
# via link_map, ASLR-aware). Candidate .so is the M1 drop-in.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
OUT=horses/libfuzzer
FH=horses/third_party/funchook
LIBS=$FH/build-cs
mkdir -p "$OUT"

CAND_SRC=${CANDIDATE_SRC:-$ROOT/horses/src/horse_candidate.c}

# funchook + capstone (S2-pinned, capstone backend)
if [ ! -f "$LIBS/libfunchook.a" ]; then
    cmake -S "$FH" -B "$LIBS" -DCMAKE_BUILD_TYPE=Release \
        -DFUNCHOOK_BUILD_SHARED=OFF -DFUNCHOOK_BUILD_STATIC=ON \
        -DFUNCHOOK_BUILD_TESTS=OFF -DFUNCHOOK_INSTALL=OFF \
        -DFUNCHOOK_DISASM=capstone > /tmp/funchook-cs-cmake.log 2>&1
    cmake --build "$LIBS" -j"$(nproc)" > /tmp/funchook-cs-build.log 2>&1
fi
CAPSTONE_A=$LIBS/_deps/capstone-build/libcapstone.a

# candidate .so must export BOTH leaves (fnv1a + digit_sum_u32) for hook mode
clang -O1 -g -fPIC -shared \
    "$CAND_SRC" \
    -o "$OUT/horse_candidate.so"

# hybrid harness (with funchook for FR-7 mode)
clang -O1 -g -fsanitize=fuzzer,address -fno-omit-frame-pointer -D_GNU_SOURCE \
    -I"$FH/include" \
    "$ROOT/horses/src/m2_hybrid.c" "$ROOT/horses/src/horse_original.c" \
    "$LIBS/libfunchook.a" "$CAPSTONE_A" \
    -o "$OUT/m2_hybrid" -ldl -lm

echo "built:"
ls -la "$OUT/m2_hybrid" "$OUT/horse_candidate.so"
