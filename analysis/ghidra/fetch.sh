#!/usr/bin/env bash
# Fetch + extract the pinned Ghidra build into $1 (parent of ghidra_12.2_PUBLIC).
# Idempotent: skips if already present. Verifies sha256 from PIN.txt when set.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST_PARENT=$1
PIN="$HERE/PIN.txt"
url=$(grep '^url:' "$PIN" | cut -d' ' -f2)
want=$(grep '^sha256:' "$PIN" | awk '{print $2}')
name=$(basename "$url" .zip)

cd "$DEST_PARENT"
if [ -x "$name/support/analyzeHeadless" ]; then
    echo "[fetch] $name already present" >&2
    exit 0
fi
echo "[fetch] downloading $url" >&2
curl -sL -o "/tmp/$name.zip" "$url"
if [ "$want" != "PENDING" ] && [ -n "$want" ]; then
    actual=$(sha256sum "/tmp/$name.zip" | cut -d' ' -f1)
    if [ "$actual" != "$want" ]; then
        echo "[fetch] sha256 mismatch: $actual != $want" >&2
        exit 4
    fi
fi
echo "[fetch] extracting to $DEST_PARENT/$name" >&2
unzip -q -o "/tmp/$name.zip"
echo "[fetch] done: $DEST_PARENT/$name" >&2
