#!/usr/bin/env bash
# M0 spike S2 (FR-7): redirect a function to a reimplementation with funchook,
# from a libFuzzer harness.
#
# Topology: the "original" function lives in s2_original.so (a loaded module —
# the M2 shape, where the stripped binary is loaded and its functions are
# redirected). The harness dlopens it, funchook-hooks original_add ->
# candidate_add (deliberately wrong for a==0xff), and libFuzzer hunts the bug.
#
# Discriminating signal: without the hook, candidate_add never runs and no
# divergence is found; with it, the fuzzer must find a==0xff.
set -euo pipefail
cd "$(dirname "$0")/../../"
ROOT=$(pwd)
FH=horses/third_party/funchook
LIBS=$FH/build-cs            # capstone backend (see NOTES.md re: distorm)
OUT=horses/spikes/out
mkdir -p "$OUT"

# 1. Build funchook (static, capstone backend) if not already built.
if [ ! -f "$LIBS/libfunchook.a" ]; then
    cmake -S "$FH" -B "$LIBS" \
        -DCMAKE_BUILD_TYPE=Release \
        -DFUNCHOOK_BUILD_SHARED=OFF -DFUNCHOOK_BUILD_STATIC=ON \
        -DFUNCHOOK_BUILD_TESTS=OFF -DFUNCHOOK_INSTALL=OFF \
        -DFUNCHOOK_DISASM=capstone > /tmp/funchook-cs-cmake.log 2>&1
    cmake --build "$LIBS" -j"$(nproc)" > /tmp/funchook-cs-build.log 2>&1
fi
CAPSTONE_A=$LIBS/_deps/capstone-build/libcapstone.a

# 2. Build the "original" (loaded module) and the libFuzzer harness.
clang -O2 -fPIC -shared horses/spikes/s2_original.c -o "$OUT/s2_original.so"
clang -O1 -fsanitize=fuzzer -I "$FH/include" horses/spikes/spike_s2.c \
    "$LIBS/libfunchook.a" "$CAPSTONE_A" -o "$OUT/spike_s2" -ldl -lm -lutil
echo "built $OUT/spike_s2 + $OUT/s2_original.so"

# 3. Build the clean negative control (correct reimplementation -> 0 divergences)
#    and remove any stale crash artifacts from prior runs.
rm -f "$OUT"/crash-* "$OUT"/oops-*
clang -O1 -fsanitize=fuzzer -DS2_CORRECT -I "$FH/include" horses/spikes/spike_s2.c \
    "$LIBS/libfunchook.a" "$CAPSTONE_A" -o "$OUT/spike_s2_correct" -ldl -lm -lutil

# 4. Run A (buggy reimpl): the fuzzer MUST find a divergence at a==0xff.
echo "=== A) buggy reimplementation — expect DIVERGENCE ==="
( cd "$OUT" && ./spike_s2 -runs=200000 -max_total_time=15 ) 2>&1 | \
    grep -E "S2: hook|DIVERGENCE|Done" | head -4 || true
rm -f "$OUT"/crash-* "$OUT"/oops-*

# 5. Run B (correct reimpl): expect NO divergence across the whole budget.
echo "=== B) correct reimplementation — expect zero divergences ==="
( cd "$OUT" && ./spike_s2_correct -runs=200000 -max_total_time=15 ) 2>&1 | \
    grep -E "S2: hook|DIVERGENCE|Done" | head -4 || true
