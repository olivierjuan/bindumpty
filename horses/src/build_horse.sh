#!/usr/bin/env bash
# horses/src/build_horse.sh — build the M1 differential harness + candidate .so.
#
#   1. harness + original  : m1_harness.c + horse_original.c (ground truth)
#        -> horses/libfuzzer/harness (libFuzzer, ASan/UBSan)
#   2. candidate           : horse_candidate.c (the agent's source)
#        -> horses/libfuzzer/horse_candidate.so (drop-in regenerable)
#
# Env: CANDIDATE_SRC (default horses/src/horse_candidate.c)
# Exit 0 on successful build of both; nonzero with the compiler's error.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
OUT=horses/libfuzzer
mkdir -p "$OUT"

CAND_SRC=${CANDIDATE_SRC:-$ROOT/horses/src/horse_candidate.c}

# 1. harness + original (differential oracle), libFuzzer persistent mode.
clang -O1 -g -fsanitize=fuzzer,address -fno-omit-frame-pointer \
    -I"$ROOT/horses/include" \
    "$ROOT/horses/src/m1_harness.c" "$ROOT/horses/src/horse_original.c" \
    -o "$OUT/harness"

# 2. candidate shared library (the leaf reimplemented by the agent).
clang -O1 -g -fPIC -shared \
    "$CAND_SRC" -o "$OUT/horse_candidate.so"

echo "built:"
ls -la "$OUT/harness" "$OUT/horse_candidate.so"
