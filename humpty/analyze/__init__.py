"""humpty.analyze — binary loaders and execution backends.

D4 — Cross-platform Windows PE execution on Linux:
- pe_loader:   direct load of pure routines (mmap RWX + ms_abi pointers)
- pe_emulator: Unicorn CPU emulator fallback (isolation/unknown instrs)
- pe_wine:     Wine headless runner (Win32-dependent targets)
"""
