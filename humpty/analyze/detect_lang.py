"""humpty.analyze.detect_lang — C vs C++ source-language detector (FR-1 aux).

The pipeline adapts to the input: a binary built from **C++** sources needs
RTTI/vtable recovery, mangled-name demangling, and a much larger fingerprint
corpus (FR-1, FR-2); a binary built from **C** sources needs none of that
(all direct calls, plain symbols). The adapter's behavior is keyed on the
verdict of this module, so the detector must be cheap, evidence-weighted and
conservative — never a bare guess.

Two tiers
---------
1. **Ghidra (authority).** `DetectSourceLang.java` runs inside the headless
   session we open for ingestion anyway and inspects what Ghidra's analysis
   actually recovered: Itanium-mangled symbols, demangled C++ names, RTTI
   recovery artifacts, C++-runtime imports. Its verdict wins.
2. **ELF pre-filter (this module, `elf_language`).** Pure-stdlib scan of
   DT_NEEDED / dynamic symbols / mangled-name strings — runs in milliseconds,
   no Ghidra session needed. Used (a) before any session is opened, to plan
   the session (e.g. enable the C++ analyzer options), and (b) as the
   fallback when no Ghidra verdict is available.

`detect_language` combines them: both tiers agree  -> that verdict, high
confidence; disagree                               -> the Ghidra verdict wins,
medium confidence (and the disagreement itself is recorded, so a silent
misadaptation is impossible — NFR-2).

Verdict model
-------------
    "c"        nothing C++-specific above noise
    "cpp"      C++ strongly evidenced (runtime linkage, mangled symbols,
               RTTI recovery)
    "lean_cpp" probably C++ — evidence present but thin (e.g. -fno-rtti
               -fno-exceptions -fvisibility=hidden: no mangled names
               surfaced, but libstdc++/libgcc_s are still linked). The
               pipeline still adapts (FR-12 layouts, demangling attempts)
               but with reduced confidence.

Usage
-----
    v = detect_language("path/to/elf")          # combined (Ghidra if avail.)
    v = elf_language("path/to/elf")             # pre-filter only
    v.verdict     # "c" | "cpp" | "lean_cpp"
    v.score       # numeric evidence sum (diagnostics)
    v.evidence    # list of Signal(name, weight, detail), auditable (NFR-2)
    v.confidence  # "high" | "medium" | "low"
"""
from __future__ import annotations

import json
import re
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["LangVerdict", "detect_language", "elf_language", "Signal",
           "ghidra_language"]


@dataclass(frozen=True)
class Signal:
    """One piece of evidence: name, weight (+ C++, - C), detail."""

    name: str
    weight: float
    detail: str


@dataclass
class LangVerdict:
    verdict: str  # "c" | "cpp" | "lean_cpp"
    score: float
    confidence: str  # "high" | "medium" | "low"
    evidence: list[Signal] = field(default_factory=list)
    tier: str = "elf"  # which tier produced this: "elf" | "ghidra" | "combined"


def _threshold_verdict(score: float) -> tuple[str, str]:
    if score >= 2.0:
        return "cpp", "high"
    if score > 0.0:
        return "lean_cpp", "medium"
    return ("c", "high") if score <= -1.0 else ("c", "medium")


# --- ELF parsing (stdlib-only; no pyelftools dependency) --------------------

_SHT_DYNSYM = 11
_PT_DYNAMIC = 2
_DT_NEEDED = 1
_DT_STRTAB = 5


def _parse_sections(data: bytes) -> list[dict]:
    """Minimal ELF64 section header parse: name + type + raw bytes."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2:  # EI_CLASS == ELFCLASS64
        raise ValueError("only ELF64 supported (x86-64 scope)")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def sh(i: int) -> dict:
        off = e_shoff + i * e_shentsize
        name, typ = struct.unpack_from("<II", data, off)
        flags = struct.unpack_from("<Q", data, off + 0x08)[0]
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


def _dynamic_entries(data: bytes, sections: list[dict]) -> list[tuple[int, int]]:
    """Return (tag, val) pairs from PT_DYNAMIC via its section mapping."""
    # .dynamic is SHT_DYNAMIC (6) in section headers — simpler than program
    # headers and equivalent for our purposes.
    for s in sections:
        if s["type"] == 6:  # SHT_DYNAMIC
            raw = data[s["offset"] : s["offset"] + s["size"]]
            return [
                (tag, val)
                for tag, val in struct.iter_unpack("<qQ", raw[: len(raw) // 16 * 16])
                if tag != 0
            ]
    return []


def _dynstr(data: bytes, sections: list[dict]) -> bytes:
    ents = _dynamic_entries(data, sections)
    strtab = next((v for t, v in ents if t == _DT_STRTAB), None)
    if strtab is None:
        return b""
    # translate the DT_STRTAB vaddr into the containing section's bytes
    for s in sections:
        if s["type"] == 8:  # SHT_NOBITS has no file bytes
            continue
        addr = s.get("addr", 0)
        if addr <= strtab < addr + s["size"]:
            off = strtab - addr
            return data[s["offset"] + off : s["offset"] + s["size"]]
    return b""


# --- signals ----------------------------------------------------------------

_MANGLED = re.compile(r"_Z[A-Z]|_ZN|_ZS|_ZT[A-Z]")
_GLIBCXX = re.compile(r"libstdc\+\+")
# __cxa_finalize is emitted by EVERY glibc binary (libc cleanup hook), and
# __cxa_atexit appears in any binary compiled with -fno-exceptions too (glibc
# registers static dtors through it), so both prove nothing on their own.
# The discriminating C++-ABI symbols are __gxx_personality_v0 (exceptions),
# __cxa_throw/catch (exceptions), _ZTI*/_ZTV* (typeinfo/vtables) and _Z*
# (mangled names) — undefined references to these exist only in C++ objects.
_CXXABI = re.compile(
    r"__gxx_|__cxa_(throw|catch|allocate|free|begin|end)|_ZT[A-Z]|^_Z|_ZGT")
_CXX_RUNTIME_NEEDED = re.compile(r"libstdc\+\+\.so")
_C_RUNTIME_ONLY = re.compile(r"libc\.so")


def elf_language(elf_path: str | Path) -> LangVerdict:
    """Tier-1 pre-filter: pure-stdlib ELF scan (no Ghidra). Fast, auditable,
    conservative. See module docstring for the evidence model."""
    path = Path(elf_path)
    data = path.read_bytes()
    sections = _parse_sections(data)
    evidence: list[Signal] = []
    score = 0.0

    # 1. DT_NEEDED: C++ runtime linkage is the strongest structural signal.
    #    A C binary never links libstdc++ (a pure-C program has no reason
    #    to; the compiler driver only adds it for C++ inputs).
    ents = _dynamic_entries(data, sections)
    strtab = _dynstr(data, sections)
    needed: list[str] = []
    for tag, val in ents:
        if tag == _DT_NEEDED and strtab:
            end = strtab.index(b"\x00", val)
            needed.append(strtab[val:end].decode(errors="replace"))
    if any(_CXX_RUNTIME_NEEDED.search(n) for n in needed):
        score += 3.0
        evidence.append(Signal("dt_needed_libstdcxx", +3.0, ",".join(needed)))
    elif needed and not any("libstdc++" in n for n in needed):
        score -= 1.0
        evidence.append(Signal("dt_needed_no_cxx_runtime", -1.0, ",".join(needed)))

    # 2. Undefined dynamic symbols (_Z*, __cxa_*, __gxx_*): only a C++ object
    #    references these. Count a bounded sample for the detail line.
    dynsym = _section_bytes(data, sections, ".dynsym")
    dynstr = _section_bytes(data, sections, ".dynstr")
    cxx_syms: list[str] = []
    if dynsym and dynstr:
        entsz = 24
        for off in range(0, len(dynsym) - entsz + 1, entsz):
            st_name = struct.unpack_from("<I", dynsym, off)[0]
            if st_name == 0 or st_name >= len(dynstr):
                continue
            end = dynstr.index(b"\x00", st_name)
            name = dynstr[st_name:end].decode(errors="replace")
            if _CXXABI.search(name) or name.startswith("_Z"):
                cxx_syms.append(name)
                if len(cxx_syms) >= 8:
                    break
    if cxx_syms:
        score += 2.0
        evidence.append(
            Signal("dynsym_cxx_symbols", +2.0, f"{len(cxx_syms)} e.g. {cxx_syms[0]}")
        )
    elif dynsym:
        score -= 0.5
        evidence.append(Signal("dynsym_no_cxx_symbols", -0.5, ""))

    # 3. Mangled-name strings anywhere (weakest, string-heuristic).
    blob = b" ".join(
        filt for filt in (_section_bytes(data, sections, ".rodata"), dynstr) if filt
    )
    mangled = len(_MANGLED.findall(blob.decode(errors="replace")))
    if mangled >= 3:
        score += 1.0
        evidence.append(Signal("mangled_names_rodata", +1.0, f"{mangled} hits"))
    elif mangled == 0:
        score -= 0.25
        evidence.append(Signal("no_mangled_names", -0.25, ""))

    # 4. .comment compiler id (weak; useful as a tiebreaker detail only).
    comment = _section_bytes(data, sections, ".comment")
    if comment:
        ids = comment.decode(errors="replace")
        if "GCC" in ids and "clang" not in ids.lower():
            evidence.append(Signal("comment_gcc", 0.0, ids.strip()))

    if score >= 2.0:
        verdict, confidence = "cpp", "high"
    elif score > 0.0:
        verdict, confidence = "lean_cpp", "medium"
    else:
        verdict, confidence = "c", "high" if score <= -1.0 else "medium"
    return LangVerdict(verdict=verdict, score=score, confidence=confidence,
                       evidence=evidence, tier="elf")


# --- tier 2: Ghidra verdict (authority) --------------------------------------

def ghidra_language(verdict_json: str | Path) -> LangVerdict:
    """Read the verdict DetectSourceLang.java wrote (inside the headless
    session). Raises FileNotFoundError if the script hasn't run."""
    obj = json.loads(Path(verdict_json).read_text())
    v = obj.get("verdict", "c")
    return LangVerdict(
        verdict=v,
        score=float(obj.get("score", 0.0)),
        confidence=obj.get("confidence", "low"),
        evidence=[Signal("ghidra:" + e.split(":")[0], 0.0, e)
                  for e in obj.get("evidence", [])],
        tier="ghidra",
    )


def detect_language(elf_path: str | Path,
                    ghidra_json: str | Path | None = None) -> LangVerdict:
    """Combined verdict: Ghidra (tier 2) is the authority when its JSON is
    supplied; the ELF scan (tier 1) is the pre-filter and the fallback.

    Agreement  -> that verdict, high confidence.
    Disagreement -> Ghidra wins, medium confidence, and the disagreement is
                    recorded as evidence so a misadaptation is visible.
    """
    elf = elf_language(elf_path)
    if ghidra_json is None:
        return elf
    gh = ghidra_language(ghidra_json)
    if gh.verdict == elf.verdict:
        return LangVerdict(verdict=gh.verdict, score=gh.score,
                           confidence="high",
                           evidence=elf.evidence + gh.evidence,
                           tier="combined")
    return LangVerdict(verdict=gh.verdict, score=gh.score,
                       confidence="medium",
                       evidence=[Signal("tier_disagreement", 0.0,
                                        f"elf={elf.verdict} ghidra={gh.verdict}")]
                       + elf.evidence + gh.evidence,
                       tier="combined")
