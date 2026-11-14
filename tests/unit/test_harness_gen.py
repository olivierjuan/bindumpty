"""Unit: humpty.king.harness_gen — per-binary harness generation."""
import json
import os

from humpty.king.harness_gen import generate_harness, HarnessError

DOC = {
    "format": "fuz.call-graph/1",
    "binary": {"sha256": "0" * 64, "arch": "x86-64", "kind": "elf"},
    "functions": [
        {"name": "fnv1a", "address": "0x11d0", "size": 48,
         "demangled_sig": "uint32_t fnv1a(const uint8_t *, unsigned long)"},
        {"name": "digit_sum_u32", "address": "0x1200", "size": 64,
         "demangled_sig": "int digit_sum_u32(uint32_t)"},
        {"name": "checksum_block", "address": "0x1240", "size": 80,
         "demangled_sig": "uint32_t checksum_block(const uint8_t *, unsigned long)"},
        {"name": "weird", "address": "0x1290", "size": 10,
         "demangled_sig": "std::vector<int> weird(std::string)"},
    ],
    "edges": [
        {"caller": "checksum_block", "callee": "fnv1a", "kind": "direct"},
        {"caller": "checksum_block", "callee": "digit_sum_u32", "kind": "direct"},
    ],
}


def test_generate_root_scoped(tmp_path):
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps(DOC))
    res = generate_harness(cg, "bin", tmp_path / "h", root_symbol="checksum_block")
    # root + transitive callees only
    assert set(res.functions) == {"checksum_block", "fnv1a", "digit_sum_u32"}
    src = res.harness_c.read_text()
    assert "static uint32_t (*g_orig_checksum_block)(" in src  # fn-pointer decl
    assert "resolve_original(0x1240" in src
    assert "resolve_original(0x11d0" in src
    assert "dlopen(" in src


def test_unsupported_signatures_reported(tmp_path):
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps(DOC))
    res = generate_harness(cg, "bin", tmp_path / "h")  # no root: all functions
    assert "weird" in res.unsupported  # std::vector<int> ret not in v0 ABI map
    assert "fnv1a" in res.functions


def test_generated_harness_compiles(tmp_path):
    import subprocess
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps(DOC))
    res = generate_harness(cg, "bin", tmp_path / "h")
    # the harness includes funchook-free resolution only; compile standalone
    r = subprocess.run(["clang", "-O1", "-fsyntax-only", "-D_GNU_SOURCE",
                        str(res.harness_c)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
