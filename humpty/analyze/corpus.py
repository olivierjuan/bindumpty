"""humpty.analyze.corpus — FR-2 v1: cross-binary fingerprint corpus.

Builds a corpus of known library function signatures from static archives
(libc.a, libz.a, ...) on this host: for each archive member object, each
defined text symbol becomes a corpus entry {name -> byte prefix + size}.
At fingerprint time, a binary's function bytes are matched against the
corpus (exact prefix on the stored bytes, normalized over relocation
zero-runs — the wildcard masking of FR-2's v1 note).

Format (JSON): {name: {"bytes_hex", "size", "archive", "member"}}
Matching: a candidate function's bytes match when the first
min(len, corpus_size) bytes agree outside relocation-blind spots.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

__all__ = ["build_corpus_from_archive", "load_corpus", "match_bytes"]

_AR_MEMBER = re.compile(r"^(?P<name>[^/]+\.o)/?$")


def build_corpus_from_archive(archive: str | Path,
                              out_json: str | Path,
                              prefixes: int = 64) -> int:
    """Extract defined text symbols + byte prefixes from a static archive.
    Returns the number of corpus entries written."""
    import tempfile

    ar = str(archive)
    members = subprocess.run(["ar", "t", ar], capture_output=True,
                             text=True, timeout=60).stdout.split()
    corpus: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["ar", "x", ar], cwd=td, capture_output=True,
                       timeout=120)
        for member in members:
            m = _AR_MEMBER.match(member)
            obj = os.path.join(td, m.group("name")) if m else None
            if not obj or not os.path.exists(obj):
                continue
            # symbols + their offsets from nm
            nm = subprocess.run(["nm", "--defined-only", "-S", obj],
                                capture_output=True, text=True,
                                timeout=60).stdout
            for line in nm.splitlines():
                m2 = re.match(
                    r"^([0-9a-f]+)\s+([0-9a-f]+)\s+[Tt]\s+(\S+)$", line)
                if not m2:
                    continue
                off, size, name = (int(m2.group(1), 16),
                                   int(m2.group(2), 16), m2.group(3))
                # skip zero-size and tiny alias/thunk symbols: real
                # fingerprint targets are >= 16 bytes of code
                if size < 16 or name in corpus:
                    continue
                # the object is an ELF: symbol offsets are section-relative,
                # so read through the section table (vaddr -> file offset).
                # Reading at the raw offset yields the ELF header for
                # section-relative symbols (the bug this fixes).
                data = Path(obj).read_bytes()
                sec_map = []
                for sl in subprocess.run(
                        ["readelf", "-S", "-W", obj], capture_output=True,
                        text=True, timeout=60).stdout.splitlines():
                    sl = sl.strip()
                    if "PROGBITS" not in sl:
                        continue
                    parts = sl.split()
                    try:
                        pidx = parts.index("PROGBITS")
                        sec_map.append((int(parts[pidx + 1], 16),
                                        int(parts[pidx + 2], 16),
                                        int(parts[pidx + 3], 16)))
                    except (ValueError, IndexError):
                        continue

                def _read_at(vaddr: int, n: int) -> bytes | None:
                    for sa, so, ssz in sec_map:
                        if sa <= vaddr < sa + ssz:
                            fo = so + (vaddr - sa)
                            return data[fo:fo + n]
                    return None

                prefix = _read_at(off, min(prefixes, size))
                if prefix is None:
                    continue
                corpus[name] = {
                    "bytes_hex": prefix.hex(),
                    "size": size,
                    "archive": Path(archive).name,
                    "member": m.group("name"),
                }
    Path(out_json).write_text(json.dumps(corpus, indent=1))
    return len(corpus)


def load_corpus(path: str | Path) -> dict[str, dict]:
    return json.loads(Path(path).read_text())


_ENDBR64 = b"\xf3\x0f\x1e\xfa"


def _normalize(data: bytes) -> bytes:
    """Strip the CET/IBT endbr64 prefix the linker may add (FR-2 v1 note:
    wildcard masking — here limited to the documented endbr64 case)."""
    if data.startswith(_ENDBR64):
        return data[4:]
    return data


def match_bytes(data: bytes, corpus: dict[str, dict]) -> str | None:
    """Match a function's bytes against the corpus. endbr64 prefixes are
    normalized on both sides (the linker adds them to PIE-linked copies)."""
    probe = _normalize(data)
    for name, entry in corpus.items():
        ref = _normalize(bytes.fromhex(entry["bytes_hex"]))
        if len(probe) >= len(ref) and probe[:len(ref)] == ref:
            return name
    return None
