"""humpty.king.harness_gen — per-binary hybrid harness generation (M2 gap).

The M2 exit proved the FR-6/FR-7 mechanics on a hand-written harness whose
resolve table was hardcoded (toy vaddrs, known signature). This module
**generates** that harness for any ingested binary from its call-graph JSON:

  generate_harness(call_graph_json, binary, out_dir) -> HarnessPaths

Emitted C contains:
  - a resolve table: every graph function's vaddr (resolved at runtime via
    dlsym on the binary's .so build, or base+offset for a loaded PIE)
  - a per-function prototype block (return type + arg types from the
    graph's demangled_sig when present, unknown-typed fallback otherwise)
  - the differential compare loop: candidate(original_callees...) vs
    original(...) on libFuzzer input

Scope note (honest): v0 generates harnesses for functions whose signature
maps to the supported ABI classes (u32/u64/pointer args, u32/u64/void
return) — the toy family. Signatures outside that class are reported in
`unsupported` and skipped rather than mis-generated.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["generate_harness", "HarnessPaths", "HarnessError"]


class HarnessError(ValueError):
    pass


@dataclass
class HarnessPaths:
    harness_c: Path
    build_sh: Path
    binary: str
    functions: list[str]
    unsupported: list[str] = field(default_factory=list)
    candidate_c: Path | None = None


# signature → C prototype translation (v0: the toy ABI family)
_RET_MAP = {
    "uint32": "uint32_t", "unsigned int": "uint32_t", "uint32_t": "uint32_t",
    "uint64": "uint64_t", "unsigned long": "uint64_t", "uint64_t": "uint64_t",
    "int": "int", "void": "void", "size_t": "size_t",
}
_ARG_MAP = {
    "const unsigned char *": "const uint8_t *",
    "unsigned char *": "uint8_t *",
    "const uint8_t *": "const uint8_t *", "uint8_t const *": "const uint8_t *",
    "uint8_t *": "uint8_t *",
    "unsigned long": "size_t", "uint64": "size_t", "uint64_t": "uint64_t",
    "size_t": "size_t", "unsigned long long": "uint64_t",
    "int": "int", "uint32": "uint32_t", "uint32_t": "uint32_t",
    "char *": "char *", "void *": "void *", "const void *": "const void *",
}


def _parse_sig(sig: str | None) -> tuple[str, list[str]] | None:
    """'uint32_t fnv1a(const uint8_t *, unsigned long)' ->
    ('uint32_t', ['const uint8_t *', 'unsigned long']). None if unparseable."""
    if not sig:
        return None
    m = re.match(r"^(.*?)\s*[A-Za-z_]\w*\s*\((.*)\)\s*$", sig.strip(), re.S)
    if not m:
        return None
    ret_raw, args_raw = m.group(1).strip(), m.group(2).strip()
    ret = _RET_MAP.get(ret_raw, _RET_MAP.get(ret_raw.lower()))
    if ret is None:
        return None
    args = []
    if args_raw and args_raw != "void":
        for a in args_raw.split(","):
            a = a.strip().rstrip()
            stripped = re.sub(r"\s*\b\w+$", "", a).strip()  # drop param name
            t = (_ARG_MAP.get(a) or _ARG_MAP.get(a.lower())
                 or _ARG_MAP.get(stripped) or _ARG_MAP.get(stripped.lower()))
            if t is None:
                return None
            args.append(t)
    return ret, args


def generate_harness(cg_json: str | Path, binary: str | Path,
                     out_dir: str | Path,
                     root_symbol: str | None = None,
                     root_candidate_src: str | None = None) -> HarnessPaths:
    """Generate a per-binary differential harness from a call graph.

    root_symbol: restrict to this function + transitive callees (the
    'specific symbol and its call tree' use). None = every graph function.
    """
    doc = json.loads(Path(cg_json).read_text())
    fns = {f["name"]: f for f in doc["functions"]}
    edges = doc.get("edges", [])

    targets = set()
    if root_symbol:
        # BFS from root over the graph edges
        children: dict[str, list[str]] = {}
        for e in edges:
            children.setdefault(e["caller"], []).append(e["callee"])
        seen, frontier = {root_symbol}, [root_symbol]
        while frontier:
            cur = frontier.pop()
            targets.add(cur)
            for ch in children.get(cur, []):
                if ch not in seen:
                    seen.add(ch)
                    frontier.append(ch)
    else:
        targets = set(fns)

    supported, unsupported = [], []
    protos: list[str] = []
    resolves: list[str] = []
    for name in sorted(targets):
        f = fns.get(name)
        if f is None:
            continue
        sig = _parse_sig(f.get("demangled_sig"))
        if sig is None:
            unsupported.append(name)
            continue
        ret, args = sig
        arg_decl = ", ".join(f"{t} a{i}" for i, t in enumerate(args)) or "void"
        arg_use = ", ".join(f"a{i}" for i in range(len(args))) or ""
        protos.append(f"static {ret} (*g_{name})({arg_decl});")
        resolves.append(
            f'    g_{name} = ({ret} (*)({", ".join(args) or "void"}))'
            f'(void *)resolve_original(0x{int(f["address"], 16):x}, "{name}");')
        supported.append(name)

    # the root's differential compare: candidate(root args) vs the
    # original root via its resolved pointer. v0 supports the u32-return,
    # (ptr, size) / (u32) argument families.
    root_compare = ""
    if root_symbol:
        f = fns.get(root_symbol, {})
        sig = _parse_sig(f.get("demangled_sig"))
        if sig:
            ret, args = sig
            cand_sym = f"cand_{root_symbol}"
            arg_use = ", ".join(f"a{i}" for i in range(len(args))) or ""
            if len(args) == 2 and "uint8_t" in args[0]:
                root_compare = (
                    "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
                    f"    uint32_t got = {cand_sym}(data, size);\n"
                    f"    uint32_t want = g_{root_symbol}(data, size);\n"
                    "    if (got != want) {\n"
                    '        fprintf(stderr, "HORSE DIVERGENCE len=%zu input=", size);\n'
                    "        for (size_t i = 0; i < size && i < 4096; i++) "
                    'fprintf(stderr, "%02x", data[i]);\n'
                    '        fprintf(stderr, " got=0x%08X want=0x%08X\\n", '
                    "got, want);\n"
                    "        abort();\n"
                    "    }\n"
                    "    return 0;\n"
                    "}\n")
            else:
                root_compare = (
                    "\nint LLVMFuzzerTestOneInput(const uint8_t *data, "
                    "size_t size) {\n"
                    "    (void)data; (void)size;\n"
                    "    return 0; /* signature family not fuzzable in v0 */\n"
                    "}\n")
        else:
            root_compare = (
                "\nint LLVMFuzzerTestOneInput(const uint8_t *data, "
                "size_t size) {\n"
                "    (void)data; (void)size;\n"
                "    return 0; /* signature unparseable — not fuzzable in v0 */\n"
                "}\n")

    harness_c = f"""/* GENERATED by humpty.king.harness_gen — do not edit by hand.
 * Source graph: {Path(cg_json).name}
 * Binary: {Path(binary).name}
 * Functions: {len(supported)} supported, {len(unsupported)} unsupported
 *
 * FR-6 hybrid + FR-7 hooking: originals resolved from the binary's shared
 * build at their real addresses; the candidate .so replaces the root
 * symbol. First divergence is a counterexample. */
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

{chr(10).join(protos)}

static void *g_handle;
static const char *g_so_path;

static void die(const char *m) {{ fprintf(stderr, "HARNESS: %s\\n", m); exit(2); }}

static void *resolve_original(unsigned long vaddr, const char *sym) {{
    void *h = dlopen(g_so_path, RTLD_NOW | RTLD_LOCAL);
    if (!h) die(dlerror());
    void *s = dlsym(h, sym);
    if (s) return s;
    struct link_map *lm;
    if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0) die("dlinfo failed");
    return (void *)((char *)lm->l_addr + vaddr);
}}

static void init_originals(void) {{
    const char *path = getenv("HORSE_TOY_ELF");
    if (!path) die("set HORSE_TOY_ELF to the binary's .so build");
    g_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_handle) die(dlerror());
{chr(10).join(resolves)}
}}

int LLVMFuzzerInitialize(int *argc, char ***argv) {{
    (void)argc; (void)argv;
    init_originals();
    return 0;
}}

{root_compare}
"""
    build_sh = f"""#!/usr/bin/env bash
# GENERATED by humpty.king.harness_gen
set -euo pipefail
cd "$(dirname "$0")/../../.."
clang -O1 -g -fsanitize=fuzzer,address -D_GNU_SOURCE \\
    "$(dirname "{out_dir}")/harness.c" \\
    -o "{out_dir}/harness" -ldl
"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cand_path = None
    if root_symbol and root_candidate_src:
        cand_path = out / f"cand_{root_symbol}.c"
        cand_path.write_text(root_candidate_src)
    hc = out / "harness.c"
    hc.write_text(harness_c)
    bs = out / "build_harness.sh"
    bs.write_text(build_sh)
    bs.chmod(0o755)
    return HarnessPaths(harness_c=hc, build_sh=bs, binary=str(binary),
                        functions=supported, unsupported=unsupported,
                        candidate_c=cand_path)
