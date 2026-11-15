"""humpty.analyze.library_filter — FR-2 Tier 1: instant symbol-pattern pruning.

For unstripped or partially-symbolized binaries, vendor and runtime
routines are identifiable from their symbol names alone — zero cost,
fully deterministic, no LLM, no fuzzer. lpex2 alone carries 1,600+
such symbols (Intel runtime, MKL, Expat, embedded SQLite, zlib,
Netlib BLAS, libc), all of which CEGIS must not waste synthesis
budget on.

Matching rows get, immediately at ingest:
    state       -> trusted            (never a synthesis target)
    confidence  -> 1.0
    fingerprint -> "vendor::<family>"

The fingerprint is recorded so the tree view can distinguish
"trusted because matched byte-for-byte against a corpus" from
"trusted because the name proves the vendor".

Tier 2 (p-code / thunk / string-reference heuristics for stripped
binaries) builds on this module later; Tier 3 (pipeline integration)
calls prune_libraries() right after call-graph ingest.
"""
from __future__ import annotations

import re

__all__ = ["LIBRARY_PATTERNS", "classify_symbol", "prune_libraries"]

# Tier 1 — symbol patterns, checked against the raw symbol name.
# Ordered by family; the first match wins and names the fingerprint.
LIBRARY_PATTERNS: list[tuple[str, str]] = [
    # Intel runtime + compiler intrinsics
    (r"^__(intel|libm|libirc|cxa|gxx|isoc99)_", "intel_runtime"),
    (r"^__intel$", "intel_runtime"),
    # Intel MKL internal dispatch
    (r"^(mkl_|MKL_)", "mkl"),
    # Expat XML parser
    (r"^(XML_|xml_)", "expat"),
    # Embedded SQLite
    (r"^sqlite3", "sqlite"),
    # zlib compression
    (r"^(deflate|inflate|adler32|crc32|zlib_)", "zlib"),
    # Netlib BLAS (Fortran-lowercase and C-uppercase conventions)
    (r"^(daxpy|ddot|dgemm|dgemv|dscal|dnrm2|dtrsm|dcopy|idamax)_?$", "blas"),
    (r"^(DAXPY|DDOT|DGEMM|DGEMV|DSCAL|DNRM2|DTRSM|DCOPY|IDAMAX)", "blas"),
    # Standard libc
    (r"^(memcpy|memset|memmove|memcmp|strlen|strcpy|strcmp|malloc|free)"
     r"(@?@?plt)?$", "libc"),
]

_COMPILED = [(re.compile(pat), fam) for pat, fam in LIBRARY_PATTERNS]


def classify_symbol(name: str) -> str | None:
    """Return the library family for a symbol name, or None.

    Demangles nothing: callers pass the symbol as the analyzer emitted
    it (the ingest bar already carries both mangled and demangled
    forms; the demangled form is the better signal and is tried first
    by prune_libraries).
    """
    for pat, fam in _COMPILED:
        if pat.search(name):
            return fam
    return None


def prune_libraries(session, *, binary_sha256: str, log=print) -> dict:
    """Tier 1 pruning over one binary's Function rows.

    Marks every row whose name (or demangled signature's function name)
    matches a library pattern:
        state=trusted, confidence=1.0, fingerprint='vendor::<family>'
    Emits one 'library_pruned' event per row (cheap, keeps the audit
    trail). Caller commits. Returns counts for the run report.
    """
    from humpty.db.models import Function
    from humpty.db.events import record_event
    from humpty.domain import State

    rows = (session.query(Function)
            .filter(Function.binary_sha256 == binary_sha256).all())
    pruned, families = 0, {}
    for fn in rows:
        candidates = [fn.name or ""]
        sig = fn.demangled_sig or ""
        if "(" in sig:
            candidates.insert(0, sig.split("(")[0].split()[-1])
        fam = None
        for cand in candidates:
            fam = classify_symbol(cand)
            if fam:
                break
        if fam is None:
            continue
        # an already-trusted row (byte-verified) keeps its fingerprint;
        # a synthesis target flips to trusted
        if fn.state == State.TRUSTED.value:
            continue
        fn.state = State.TRUSTED.value
        fn.confidence = 1.0
        fn.fingerprint = f"vendor::{fam}"
        pruned += 1
        families[fam] = families.get(fam, 0) + 1
        record_event(session, kind="library_pruned", function_id=fn.id,
                     payload={"family": fam, "symbol": fn.name})
    if pruned:
        log(f"FR-2 Tier 1: pruned {pruned} library functions "
            + ", ".join(f"{k}={v}" for k, v in sorted(families.items(),
                                                        key=lambda x: -x[1])))
    return {"pruned": pruned, "families": families}
