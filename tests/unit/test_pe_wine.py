"""D4.3: Wine headless runner — unit tests (skip when wine/mingw absent)."""
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from humpty.analyze.pe_wine import run_wine_function, wine_available

pytestmark = pytest.mark.skipif(not wine_available(),
                                reason="wine64/mingw not installed")

TOY_WIN_DLL = "/tmp/toy_win.dll"


def _build_dll():
    """Compile the win64 toy dll once if missing."""
    if os.path.exists(TOY_WIN_DLL):
        return
    src = r'''
#include <windows.h>
unsigned int __stdcall fnv1a(const unsigned char *d, unsigned int l) {
    unsigned int h = 2166136261u;
    for (unsigned int i = 0; i < l; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) { return TRUE; }
'''
    import tempfile
    c = tempfile.NamedTemporaryFile("w", suffix=".c", delete=False)
    c.write(src)
    c.close()
    r = subprocess.run(["x86_64-w64-mingw32-gcc", "-shared", "-O1",
                        "-o", TOY_WIN_DLL, c.name],
                       capture_output=True, text=True)
    os.unlink(c.name)
    assert r.returncode == 0, r.stderr


def test_fnv1a_matches_host_computation(tmp_path):
    _build_dll()
    r = run_wine_function(TOY_WIN_DLL, "fnv1a", b"hello world",
                          ret_width=32, workdir=tmp_path, timeout_s=90)
    assert r.exit_code == 0, r.stderr
    h = 2166136261
    for b in b"hello world":
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    assert r.ret == h


def test_missing_export_errors(tmp_path):
    _build_dll()
    r = run_wine_function(TOY_WIN_DLL, "no_such_export", b"x",
                          workdir=tmp_path, timeout_s=90)
    assert r.exit_code != 0
    assert "export not found" in r.stderr
