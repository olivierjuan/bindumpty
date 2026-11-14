"""Unit: humpty.analyze.symtree — symbol-selected call subtrees.

Uses the toy binary (built by build.sh; skipped when absent)."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.symtree import load_symbols, subtree  # noqa: E402

ELF = os.path.join(ROOT, "toys/case-01-leaf/build/toy01")
pytestmark = pytest.mark.skipif(not os.path.exists(ELF),
                                reason="toy01 not built (run build.sh)")


@pytest.fixture(scope="module")
def symbols():
    return load_symbols(ELF)


def test_subtree_from_address_anchor(symbols):
    """0x1290 (main) is never a call target — an address anchor must still
    walk its callees (bounded to the next known start)."""
    t = subtree(ELF, "fn_1290", depth=3, symbols=symbols)
    names = set(t.nodes)
    assert "fn_1240" in names and "fn_11d0" in names and "fn_1200" in names
    assert ("fn_1290", "fn_1240") in t.edges


def test_exclude_stops_traversal(symbols):
    without = subtree(ELF, "fn_1290", depth=3, symbols=symbols)
    with_excl = subtree(ELF, "fn_1290", depth=3, symbols=symbols,
                        exclude=["fn_11d0"])
    assert "fn_11d0" in set(without.nodes)
    # excluded node is present (visible) but its callees are not walked
    assert "fn_11d0" in set(with_excl.nodes)
    assert not any(a == "fn_11d0" for a, _ in with_excl.edges)


def test_exclude_accepts_glob_syntax(symbols):
    """Shell-glob patterns ('fn_1*') are accepted alongside regex."""
    t = subtree(ELF, "fn_1290", depth=3, symbols=symbols, exclude=["fn_11*"])
    assert ("fn_1290", "fn_11d0") not in t.edges


def test_exclude_invalid_regex_falls_back_to_literal(symbols):
    """'mkl_*'-style globs (nothing to repeat as regex) must not crash —
    they translate to glob matching. Plain literals work too."""
    t = subtree(ELF, "fn_1290", depth=3, symbols=symbols,
                exclude=["mkl_*", "fn_11d0"])
    assert ("fn_1290", "fn_11d0") not in t.edges


def test_symbols_on_unstripped_and_stripped(symbols):
    """The unstripped .so build resolves real names."""
    so = os.path.join(ROOT, "toys/case-01-leaf/build/toy01.so")
    if os.path.exists(so):
        syms = load_symbols(so)
        assert "fnv1a" in syms and "checksum_block" in syms
