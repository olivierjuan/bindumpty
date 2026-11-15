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


def prune_libraries(session, *, binary_sha256: str,
                    binary_path: str | Path | None = None,
                    log=print) -> dict:
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

    # Tier 2: stripped-binary thunk sweep — functions that are pure
    # jump glue (1-3 jmp instructions) are dispatch, never synthesis
    # targets. Runs once per binary; FUN_-named rows (no symbol) match
    # by address.
    thunks = find_thunks(binary_path)
    by_addr = {fn.address: fn for fn in rows}
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
        if fam is None and fn.address in thunks:
            fam = "thunk"
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


# --------------------------------------------------------------------------
# Tier 2 — stripped-binary heuristics (p-code / disassembly level)
# --------------------------------------------------------------------------

def find_thunks(binary: str | Path, min_addr: int = 0,
                max_addr: int = 2**64) -> dict[int, int]:
    """Detect PLT-style thunks: tiny functions whose body is only
    indirect jumps (jmp *%rax / bnd jmp *%rax / jmp qword ptr [rip+X]).

    Returns {thunk_addr: target_addr}. Thunks are dispatch glue, not
    synthesis targets — the caller marks them trusted with
    fingerprint 'vendor::thunk'.
    """
    import subprocess
    r = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn",
         f"--start-address=0x{min_addr:x}", f"--stop-address=0x{max_addr:x}",
         str(binary)],
        capture_output=True, text=True, timeout=600)
    thunks: dict[int, int] = {}
    cur_addr = None
    insns: list[str] = []
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+) <([^>]+)>:", line)
        if m:
            if cur_addr is not None and _is_thunk(insns):
                tgt = _thunk_target(insns)
                if tgt is not None:
                    thunks[cur_addr] = tgt
            cur_addr, insns = int(m.group(1), 16), []
            continue
        mi = re.match(r"^\s*[0-9a-f]+:\s+(.*)$", line)
        if mi and cur_addr is not None:
            insns.append(mi.group(1).strip())
    if cur_addr is not None and _is_thunk(insns):
        tgt = _thunk_target(insns)
        if tgt is not None:
            thunks[cur_addr] = tgt
    return thunks


_THUNK_JMP = re.compile(r"^\s*(?:bnd\s+)?jmp\s*\*?%?\w*$|"
                        r"^\s*(?:bnd\s+)?jmp\s+.*\*%|"
                        r"^\s*(?:bnd\s+)?jmp\s+qword ptr \[rip")


def _is_thunk(insns: list[str]) -> bool:
    """Pure jump glue: 1-3 instructions where every non-padding
    instruction is a jmp (direct or indirect), optionally fronted by a
    lazy-binding push. Genuinely callable thunks, never algorithms."""
    if not 1 <= len(insns) <= 3:
        return False
    saw_jmp = False
    for ins in insns:
        if re.match(r"^(?:bnd\s+)?jmp\b", ins):
            saw_jmp = True
            continue
        if re.match(r"^push\b", ins):     # lazy PLT stub: push + jmp
            continue
        if re.match(r"^(?:nopl?|nop\b|xchg\s+%ax,%ax)", ins):  # padding
            continue
        return False
    return saw_jmp


def _thunk_target(insns: list[str]) -> int | None:
    """Best-effort static target of the jump (register jumps return
    None — the target is a runtime pointer)."""
    last = insns[-1]
    m = re.search(r"jmp\s+(?:qword ptr \[rip\+)?(?:0x)?([0-9a-f]+)", last)
    if m:
        return int(m.group(1), 16)
    return None
