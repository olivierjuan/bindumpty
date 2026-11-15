"""P2: prototype parsing + normalization + refresh."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.ingest.prototypes import (
    normalize_sig,
    parse_kuna_header,
    parse_prototype_from_decompiled,
    sig_param_count,
)


def test_ghidra_prototype_normalized():
    code = ("undefined8 DAXPY(int *param_1, double *param_2, "
            "double *param_3, int *param_4, double *param_5)\n{\n  ...\n}\n")
    sig = parse_prototype_from_decompiled(code)
    assert sig is not None
    assert sig.startswith("uint64_t DAXPY(")
    assert "int *param_1" in sig
    assert sig_param_count(sig) == 5


def test_kuna_header():
    text = ("// Recovered: void daxpy_(int *n, double *sa, double *x, "
            "int *incx, double *y, int *incy)\n"
            "void daxpy_(int *n, double *sa, double *x, int *incx, "
            "double *y, int *incy) {\n...}\n")
    assert "void daxpy_(" in parse_kuna_header(text)


def test_undefined_pointer_type():
    sig = parse_prototype_from_decompiled(
        "void f(undefined8 *param_1, undefined *param_2) {}")
    assert "uint64_t *param_1" in sig
    assert "void *param_2" in sig


def test_no_prototype_returns_none():
    assert parse_prototype_from_decompiled("int x = 5;\n") is None
    assert parse_kuna_header("// nothing here\n") is None


def test_void_and_variadic_arity():
    assert sig_param_count("void f(void)") == 0
    assert sig_param_count("int f(int a, char *b)") == 2
    assert sig_param_count("int f(...)") == 0


def test_extract_c_from_json_envelope():
    from humpty.men.providers import _extract_c
    t = ('{"candidates": ["void f(void)\\n{\\n    return 0;\\n}", '
         '"int g(void){return 1;}"]}')
    assert _extract_c(t) == "void f(void)\n{\n    return 0;\n}"


def test_extract_c_passthrough_and_fences():
    from humpty.men.providers import _extract_c
    assert _extract_c("int i(void) { return 3; }\n") == "int i(void) { return 3; }\n"
    assert "return 2" in _extract_c("```c\nint h(void) { return 2; }\n```")
