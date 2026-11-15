"""humpty.ingest.prototypes — P2: automatic prototype & ABI normalization.

Recovering a callable prototype without hand-written `known_sigs`:

1. Ghidra decompiler prototype (best): the decompiled C's first
   signature line — even for a stripped binary Ghidra recovers calling
   convention + param count/register class from disassembly analysis.
   Types are Ghidra-flavored (undefined8, undefined*, uint, ulong ...).
2. Kuna '// Recovered:' headers: reconstructed-C corpora carry a
   one-line recovered prototype header.
3. Register analysis (System V AMD64 vs Microsoft x64): used to pick
   the calling-convention family when only arg COUNT is known — the
   param registers differ (rdi/rsi/rdx/rcx vs rcx/rdx/r8/r9), which
   harness_gen must know to build the right harness.

The normalized signature lands in functions.demangled_sig, and
harness_gen's _parse_sig picks it up with no manual intervention.
"""
from __future__ import annotations

import re

__all__ = ["parse_prototype_from_decompiled", "parse_kuna_header",
           "normalize_sig", "sig_param_count", "refresh_prototypes"]

# Ghidra flavor -> standard C99 type
_GHIDRA_TYPES = {
    "undefined": "void",
    "undefined1": "uint8_t",
    "undefined2": "uint16_t",
    "undefined4": "uint32_t",
    "undefined8": "uint64_t",
    "uchar": "uint8_t",
    "ushort": "uint16_t",
    "uint": "uint32_t",
    "ulong": "uint64_t",
    "ulonglong": "uint64_t",
    "longlong": "int64_t",
    "byte": "uint8_t",
    "word": "uint16_t",
    "dword": "uint32_t",
    "qword": "uint64_t",
    "float": "float",
    "double": "double",
    "int": "int",
    "char": "char",
    "long": "long",
    "bool": "bool",
    "code *": "void (*)(void)",
    "char *": "char *",
    "void *": "void *",
}

_PROTO_RE = re.compile(
    r"^\s*(?P<ret>[A-Za-z_][\w]*(?:\s*\*)*)\s+"
    r"(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^)]*)\)\s*"
    r"(?:[;{]\s*\}?\s*|;\s*|\{\s*\}?\s*)$")


def normalize_type(t: str) -> str:
    """One Ghidra/Kuna type token -> normalized C99 token."""
    t = t.strip().rstrip("*").strip()
    stars = "*" * (len(t.strip()) - len(t))
    t = t.strip()
    norm = _GHIDRA_TYPES.get(t, t)
    return norm + stars


def normalize_sig(sig: str) -> str:
    """Normalize a whole signature string's types (keeps name/arity)."""
    m = _PROTO_RE.match(sig.strip())
    if not m:
        return sig
    params = []
    for p in m.group("params").split(","):
        p = p.strip()
        if not p:
            continue
        if p in ("void", "..."):
            params.append(p)
            continue
        # "type name" | "type *" | "type" — keep param names when present
        toks = p.split()
        if len(toks) >= 2 and not toks[0].endswith("*"):
            ptype = normalize_type(toks[0])
            pname = " ".join(toks[1:])
            params.append(f"{ptype} {pname}")
        else:
            params.append(normalize_type(p))
    ret = normalize_type(m.group("ret"))
    return f"{ret} {m.group('name')}({', '.join(params) or 'void'})"


def parse_prototype_from_decompiled(code: str) -> str | None:
    """Extract the function's prototype line from decompiled C.

    Handles Ghidra output (types like undefined8, undefined *, offsets
    in the body) and plain C. Returns the normalized signature, or None
    when no prototype-looking line exists.
    """
    for line in code.splitlines():
        line = line.strip()
        if line.startswith(("//", "/*", "*", "#")):
            continue
        m = _PROTO_RE.match(line)
        if m and "(" in line:
            return normalize_sig(line)
    return None


_KUNA_RE = re.compile(r"^\s*//\s*Recovered:\s*(.+?)\s*$", re.M)


def parse_kuna_header(text: str) -> str | None:
    """Extract a '// Recovered: <prototype>' header (kuna convention)."""
    m = _KUNA_RE.search(text)
    if not m:
        return None
    return normalize_sig(m.group(1))


# calling-convention parameter registers (for the harness family choice)
_SYSV_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_MS_ABI_ARG_REGS = ["rcx", "rdx", "r8", "r9"]


def sig_param_count(sig: str | None) -> int:
    """Number of parameters a signature declares (float args, variadic
    -> 0 unknown)."""
    if not sig:
        return 0
    m = _PROTO_RE.match(sig.strip())
    if not m:
        return 0
    params = [p.strip() for p in m.group("params").split(",") if p.strip()]
    if params == ["void"] or not params:
        return 0
    return len([p for p in params if p != "..."])


def refresh_prototypes(session, binary: str, log=print) -> int:
    """Fill functions.demangled_sig from every available source.

    Per function row of `binary`: decompiled_code prototype first, then
    the kuna '// Recovered:' header inside it. Generic Ghidra names
    (param_1...) are kept — the arity + register family is what
    harness_gen needs; parameter names are cosmetic. Returns the count
    of rows updated. Caller commits.
    """
    from humpty.db.models import Function
    from humpty.ingest import binary_sha256

    sha = binary_sha256(binary)
    updated = 0
    for fn in (session.query(Function)
               .filter(Function.binary_sha256 == sha).all()):
        if fn.demangled_sig and "param_" not in fn.demangled_sig:
            continue  # already has a human-assigned signature
        sig = None
        if fn.decompiled_code:
            sig = parse_prototype_from_decompiled(fn.decompiled_code) \
                or parse_kuna_header(fn.decompiled_code)
        if sig and sig != fn.demangled_sig:
            fn.demangled_sig = sig
            updated += 1
            log(f"  {fn.name}: prototype <- {sig}")
    if updated:
        log(f"prototypes refreshed: {updated} rows")
    return updated
