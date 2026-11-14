"""humpty.analyze.fingerprint — FR-2 v0: known-library identification by
byte-signature matching.

FR-2: identify known library functions (STL, Boost, zlib, fmt, libc) by
signature matching, mark them ``trusted`` without LLM or fuzzing, and record
the mapping to the real function. v0 is deliberately honest about its limits:

* The corpus is seeded from a binary's *own* imported symbols (the PLT stubs
  behind ``.rela.plt``). Reference ``libc.a`` objects are not available to the
  pipeline, so v0 recognizes what a binary already imports. A PLT stub is
  GOT-relative — per-binary — so a v0 entry proves self-consistency with that
  build, not cross-binary identity. A real cross-binary corpus (objcopy
  ``.text`` of libc/zlib/... with wildcard masking) is the v1 mechanism.
* Matching is exact byte identity (no wildcards, no masking): compiler,
  flags and PIE-mode differences break matches. Documented v0 trade-off:
  zero false positives, many misses.

Corpus file format (JSON)::

    {"getenv": {"bytes_hex": "ff25...", "size": 16}, ...}

Byte-extraction decision (documented per FR-2): the function's bytes are read
*directly from the ELF* through the section vaddr->file-offset mapping — the
same bytes ``objdump -s`` prints at address+size, without a subprocess. That
keeps fingerprinting pure-stdlib and deterministic, matching the ELF-parsing
convention of :mod:`humpty.analyze.detect_lang`. Sizes come from the Function
row (the Ghidra export's ``size`` column, ingested by humpty.ingest).

State handling: on a match the row gets ``Function.fingerprint`` and, when
:func:`humpty.domain.can_transition` allows it, ``state`` moves to
``trusted``. Both happen in the caller's transaction together with the
``fingerprint_match`` event (write-in-transaction, humpty.db.events).
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from humpty.db.events import record_event
from humpty.db.models import Function
from humpty.domain import State, can_transition

__all__ = [
    "FingerprintError",
    "build_corpus_symbols",
    "build_corpus_bytes",
    "imported_symbols",
    "save_corpus",
    "load_corpus",
    "fingerprint_function",
    "fingerprint_functions",
]


class FingerprintError(ValueError):
    """The fingerprinting inputs failed validation (ELF, corpus, function)."""


# --- minimal ELF64 parsing (same stdlib-only convention as detect_lang) -----

_SHT_NOBITS = 8
_PT_JMP_SLOT = 7  # R_X86_64_JUMP_SLOT: .rela.plt entries that own a PLT slot
_PLT_STUB_SIZE = 16  # x86-64 PLT entry size; .plt[0] is the resolver header


def _parse_sections(data: bytes) -> list[dict]:
    """Minimal ELF64 section header parse (mirrors detect_lang._parse_sections,
    kept local: those helpers are module-private there)."""
    if data[:4] != b"\x7fELF":
        raise FingerprintError("not an ELF file")
    if data[4] != 2:  # EI_CLASS == ELFCLASS64
        raise FingerprintError("only ELF64 supported (x86-64 scope)")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def sh(i: int) -> dict:
        off = e_shoff + i * e_shentsize
        name, typ = struct.unpack_from("<II", data, off)
        addr, offset = struct.unpack_from("<QQ", data, off + 0x10)
        size = struct.unpack_from("<Q", data, off + 0x20)[0]
        return {"name_off": name, "type": typ, "addr": addr,
                "offset": offset, "size": size}

    sections = [sh(i) for i in range(e_shnum)]
    strtab_off = sections[e_shstrndx]["offset"]
    for s in sections:
        end = data.index(b"\x00", strtab_off + s["name_off"])
        s["name"] = data[strtab_off + s["name_off"] : end].decode()
    return sections


def _section_bytes(data: bytes, sections: list[dict], name: str) -> bytes | None:
    for s in sections:
        if s["name"] == name:
            return data[s["offset"] : s["offset"] + s["size"]]
    return None


def _vaddr_read(data: bytes, sections: list[dict], vaddr: int, size: int) -> bytes:
    """Read ``size`` bytes at virtual address ``vaddr`` from a section-backed
    mapping. NOBITS sections have no file bytes and never match."""
    for s in sections:
        if s["type"] == _SHT_NOBITS:
            continue
        if s["addr"] <= vaddr and vaddr + size <= s["addr"] + s["size"]:
            off = s["offset"] + (vaddr - s["addr"])
            return data[off : off + size]
    raise FingerprintError(f"vaddr 0x{vaddr:x}+{size} not mapped by any section")


def _dynsym_name(dynsym: bytes, dynstr: bytes, symidx: int) -> str:
    if symidx * 24 + 24 > len(dynsym):
        return ""
    st_name = struct.unpack_from("<I", dynsym, symidx * 24)[0]
    if st_name == 0 or st_name >= len(dynstr):
        return ""
    end = dynstr.index(b"\x00", st_name)
    name = dynstr[st_name:end].decode(errors="replace")
    # "getenv@GLIBC_2.2.5" -> "getenv": the plain name is the real-function
    # mapping FR-2 promises; the version tag is environment detail.
    return name.split("@", 1)[0]


# --- corpus construction -----------------------------------------------------


def imported_symbols(elf_path: str | Path) -> dict[str, tuple[int, int]]:
    """Map each imported function to its PLT stub: ``name -> (vaddr, size)``.

    The ``.rela.plt`` JUMP_SLOT entries map 1:1 (in order) to PLT slots; the
    classic x86-64 layout puts the resolver trampoline at ``.plt[0]`` and slot
    ``i`` at ``.plt + 16*(i+1)`` (verified against the case-01 toy, whose
    objdump shows ``getenv@plt`` at ``.plt+0x10``).
    """
    data = Path(elf_path).read_bytes()
    sections = _parse_sections(data)
    rela = _section_bytes(data, sections, ".rela.plt")
    dynsym = _section_bytes(data, sections, ".dynsym")
    dynstr = _section_bytes(data, sections, ".dynstr")
    plt = next((s for s in sections if s["name"] == ".plt"), None)
    if rela is None or dynsym is None or dynstr is None or plt is None:
        return {}  # statically linked or no imports: nothing to seed

    out: dict[str, tuple[int, int]] = {}
    slot = 0
    for r_offset, r_info, _addend in struct.iter_unpack(
        "<QQq", rela[: len(rela) // 24 * 24]
    ):
        if (r_info & 0xFFFFFFFF) != _PT_JMP_SLOT:
            continue
        name = _dynsym_name(dynsym, dynstr, r_info >> 32)
        if name:
            out[name] = (plt["addr"] + (slot + 1) * _PLT_STUB_SIZE, _PLT_STUB_SIZE)
        slot += 1
    return out


def build_corpus_symbols(binary_paths: list[str | Path]) -> dict[str, bytes]:
    """Seed the v0 corpus from the given binaries' own imported symbols.

    For every import, the first ``_PLT_STUB_SIZE`` bytes of its PLT stub are
    recorded. Returns ``{name: bytes}`` (deterministic order). Honest v0
    limits: see the module docstring — these are per-binary stubs, not
    cross-binary library signatures.
    """
    corpus: dict[str, bytes] = {}
    for path in binary_paths:
        data = Path(path).read_bytes()
        sections = _parse_sections(data)
        for name in sorted(imported_symbols(path)):
            vaddr, size = imported_symbols(path)[name]
            corpus[name] = _vaddr_read(data, sections, vaddr, size)
    return corpus


# --- corpus file I/O ---------------------------------------------------------


def save_corpus(corpus: dict[str, bytes], path: str | Path) -> None:
    """Write the corpus JSON ``{name: {bytes_hex, size}}`` (sorted, stable)."""
    doc = {
        name: {"bytes_hex": blob.hex(), "size": len(blob)}
        for name, blob in sorted(corpus.items())
    }
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True))


def load_corpus(path: str | Path) -> dict[str, bytes]:
    """Read the corpus JSON ``{name: {bytes_hex, size}}`` back."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise FingerprintError(f"corpus {path}: unreadable ({exc})") from exc
    if not isinstance(doc, dict):
        raise FingerprintError(f"corpus {path}: want a JSON object")
    corpus: dict[str, bytes] = {}
    for name, entry in doc.items():
        if not isinstance(entry, dict) or "bytes_hex" not in entry:
            raise FingerprintError(f"corpus {path}: entry {name!r} malformed")
        blob = bytes.fromhex(entry["bytes_hex"])
        size = entry.get("size")
        if size is not None and size != len(blob):
            raise FingerprintError(
                f"corpus {path}: {name!r} size {size} != {len(blob)} bytes"
            )
        corpus[name] = blob
    return corpus


def _match_prefix(raw: bytes, corpus: dict[str, bytes]) -> str | None:
    """First corpus name whose stored byte prefix equals ``raw`` exactly.

    The corpus records the *first bytes at a symbol's address*; a match is an
    exact-byte comparison against that prefix (zero false positives, the
    documented v0 trade-off). Ties resolve deterministically by name.
    """
    return next(
        (name for name, blob in sorted(corpus.items()) if raw[: len(blob)] == blob),
        None,
    )


# --- the FR-2 hook -----------------------------------------------------------


def fingerprint_function(
    session: Session,
    *,
    function_id: int,
    corpus_path: str | Path,
    binary_path: str | Path | None = None,
) -> str | None:
    """Match one function against the corpus (FR-2 v0). Returns the matched
    corpus name, or ``None`` on no match.

    On a match: ``Function.fingerprint`` is set to the corpus name (the
    mapping to the real function); if the lifecycle allows it
    (``humpty.domain.can_transition``), the state moves to ``trusted`` — no
    LLM, no fuzzing. The ``fingerprint_match`` event records both the match
    and whether the transition happened, in the caller's transaction.

    ``binary_path`` must be supplied: the DB stores only the binary's SHA-256
    identity, not its path (the orchestrator resolves the path from its
    artifact registry; a ``None`` here is a caller error, not a miss).
    """
    fn = session.get(Function, function_id)
    if fn is None:
        raise FingerprintError(f"function id {function_id} not found")
    if fn.size is None or fn.size <= 0:
        return None  # no bytes to hash (e.g. an external stub row without size)
    if binary_path is None:
        raise FingerprintError("binary_path is required (the DB stores no path)")

    data = Path(binary_path).read_bytes()
    raw = _vaddr_read(data, _parse_sections(data), fn.address, fn.size)
    digest = hashlib.sha256(raw).hexdigest()

    matched = _match_prefix(raw, load_corpus(corpus_path))
    if matched is None:
        return None

    fn.fingerprint = matched
    try:
        src = State(fn.state)
        transitioned = can_transition(src, State.TRUSTED)
    except ValueError:
        src, transitioned = None, False
    if transitioned:
        fn.state = State.TRUSTED.value
    record_event(
        session,
        kind="fingerprint_match",
        function_id=fn.id,
        payload={
            "match": matched,
            "sha256": digest,
            "size": fn.size,
            "from_state": src.value if src is not None else fn.state,
            "transitioned": transitioned,
        },
    )
    return matched


# --- FR-2 binary sweep -------------------------------------------------------


def _nm_layout(elf_path: str | Path) -> dict[str, dict]:
    """Parse ``nm -S -n <elf>`` into ``name -> {addr, size}``.

    Requires the GNU binutils ``nm`` (like the tests' ``_nm_addresses``). A
    missing tool or a stripped ELF (no symbol table) yields ``{}``; callers
    then need a ``layout`` map.
    """
    nm = shutil.which("nm")
    if nm is None:
        return {}
    try:
        out = subprocess.run([nm, "-S", "-n", str(elf_path)],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, OSError):
        return {}
    layout: dict[str, dict] = {}
    for line in out.splitlines():
        m = re.fullmatch(r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)",
                         line.strip())
        if m:
            layout[m.group(3)] = {
                "addr": int(m.group(1), 16), "size": int(m.group(2), 16),
            }
    return layout


def build_corpus_bytes(
    elf_path: str | Path,
    symbol_names: list[str],
    layout: dict[str, tuple[int | str, int]] | None = None,
) -> dict[str, bytes]:
    """Extract the bytes at each named symbol from a reference ELF.

    Addresses/sizes resolve per name, in order: the ``layout`` map (e.g. the
    ground-truth call graph: ``{"fnv1a": ("0x11d0", 48), ...}``), then
    ``nm -S`` on the ELF itself (unstripped reference builds). A name
    resolvable by neither raises :class:`FingerprintError` — a corpus that
    silently omits entries makes matching lie.

    The recorded bytes are the symbol's full extent — the byte prefix a later
    match compares against.
    """
    data = Path(elf_path).read_bytes()
    sections = _parse_sections(data)
    nm = _nm_layout(elf_path)

    resolved: dict[str, tuple[int, int]] = {}
    missing: list[str] = []
    for name in symbol_names:
        if layout is not None and name in layout:
            addr, size = layout[name]
            resolved[name] = (
                int(addr, 0) if isinstance(addr, str) else int(addr), int(size),
            )
        elif name in nm:
            resolved[name] = (nm[name]["addr"], nm[name]["size"])
        else:
            missing.append(name)
    if missing:
        raise FingerprintError(
            f"{elf_path}: unresolvable symbol(s) {missing}: not in layout "
            f"or nm -S output"
        )

    return {
        name: _vaddr_read(data, sections, addr, size)
        for name, (addr, size) in resolved.items()
    }


def fingerprint_functions(
    session: Session,
    *,
    binary_sha256: str,
    corpus_path: str | Path,
    binary_path: str | Path,
) -> list[str]:
    """Fingerprint every Function row of one binary (FR-2 v0, binary sweep).

    For each row whose ``binary_sha256`` matches, the function's bytes are
    read from the ELF through the section vaddr->file-offset mapping (for the
    PIE case-01 layout the .text region satisfies file offset == vaddr, and
    ``_vaddr_read`` verifies against the section table rather than assuming)
    and compared against the corpus. On a match the row gets
    ``Function.fingerprint`` and, when ``humpty.domain.can_transition``
    allows it, ``pending -> trusted``; if the transition is illegal, the
    fingerprint is still recorded and the refusal is reported through the
    ``fingerprint_match`` event payload (``transitioned: false``). Unmatched
    rows are left untouched. Returns the matched names in row-id order.
    """
    rows = session.scalars(
        select(Function).where(Function.binary_sha256 == binary_sha256)
        .order_by(Function.id)
    ).all()
    data = Path(binary_path).read_bytes()
    sections = _parse_sections(data)
    corpus = load_corpus(corpus_path)

    matched_names: list[str] = []
    for fn in rows:
        if fn.size is None or fn.size <= 0:
            continue  # nothing to hash
        raw = _vaddr_read(data, sections, fn.address, fn.size)
        matched = _match_prefix(raw, corpus)
        if matched is None:
            continue
        fn.fingerprint = matched
        try:
            src = State(fn.state)
            transitioned = can_transition(src, State.TRUSTED)
        except ValueError:
            src, transitioned = None, False
        if transitioned:
            fn.state = State.TRUSTED.value
        record_event(
            session,
            kind="fingerprint_match",
            function_id=fn.id,
            payload={
                "match": matched,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": fn.size,
                "from_state": src.value if src is not None else fn.state,
                "transitioned": transitioned,
            },
        )
        matched_names.append(matched)
    session.flush()
    return matched_names
