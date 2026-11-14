"""Unit tests: analysis.exporters multi-backend seam.

The objdump backend must reproduce the case-01 ground-truth direct-edge set
when fed the recovered name map, and degrade to fn_<vaddr> names on the
stripped binary without one. compare_backends and export_with are tested
purely in-process (hand-built ExportResults / backend-table lookup).
"""
import json
import os
import re
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from analysis.exporters import ExportResult, compare_backends, export_with  # noqa: E402
from analysis.exporters.objdump_export import objdump_call_graph  # noqa: E402

CASE = os.path.join("toys", "case-01-leaf")
GT = os.path.join(CASE, "ground_truth", "call_graph.json")
ELF = os.path.join(CASE, "build", "toy01")


def _require_artifacts():
    root = REPO
    for p in (os.path.join(root, ELF), os.path.join(root, GT)):
        if not os.path.exists(p):
            pytest.skip(f"toy artifact missing: {p} (run build.sh + record.sh)")
    if shutil.which("objdump") is None:
        pytest.skip("objdump not installed")


def _ground_truth():
    return json.load(open(os.path.join(REPO, GT)))


def test_objdump_backend_matches_ground_truth():
    _require_artifacts()
    gt = _ground_truth()
    name_map = {int(f["address"], 16): f["name"] for f in gt["functions"]}

    res = objdump_call_graph(os.path.join(REPO, ELF), name_map=name_map)

    got = {(e["caller"], e["callee"]) for e in res.edges if e["kind"] == "direct"}
    want = {(e["caller"], e["callee"]) for e in gt["edges"]}
    assert got == want


def test_objdump_backend_stripped_names():
    _require_artifacts()
    gt = _ground_truth()
    name_map = {int(f["address"], 16): f["name"] for f in gt["functions"]}

    res = objdump_call_graph(os.path.join(REPO, ELF))

    stripped = re.compile(r"fn_[0-9a-f]+\Z")
    for f in res.functions:
        assert stripped.match(f["name"]), f["name"]
    for e in res.edges:
        assert stripped.match(e["caller"]), e
        assert stripped.match(e["callee"]), e

    # The stripped names must line up with the recovered ones by address:
    # the fn at 0x1240 (checksum_block) calls the fns at 0x11d0 and 0x1200.
    edges = {(e["caller"], e["callee"]) for e in res.edges}
    expected = {(f"fn_{a:x}", f"fn_{b:x}")
                for a, b in ((0x1240, 0x11d0), (0x1240, 0x1200))}
    assert name_map[0x1240] == "checksum_block"  # guard: gt desync fails loudly
    assert expected <= edges


def test_compare_backends_disagreement():
    a = ExportResult(backend="a", source_lang="c", functions=[],
                     edges=[{"caller": "x", "callee": "y", "kind": "direct"}])
    b = ExportResult(backend="b", source_lang="c", functions=[],
                     edges=[{"caller": "x", "callee": "y", "kind": "direct"},
                            {"caller": "y", "callee": "z", "kind": "direct"}])

    verdict = compare_backends(a, b)

    assert verdict["agree"] is False
    assert verdict["only_in_b"] == [("y", "z")]


def test_unknown_backend_rejected():
    with pytest.raises(ValueError):
        export_with("nonexistent", "whatever-binary", "out.json")
