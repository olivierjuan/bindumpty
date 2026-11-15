"""humpty.analyze.pe_emulator — D4.2: Unicorn emulator fallback.

For functions that need strict isolation or contain unknown instructions:
emulate them under Unicorn Engine (CPU-level sandbox, no OS services).

Requires: `pip install unicorn` (the Unicorn CPU emulator bindings).
"""
from __future__ import annotations

import ctypes
import struct

from humpty.analyze.pe_loader import load_pe

__all__ = ["emulate_pe_function", "EmulateResult"]

# x86-64 MS ABI registers
REG_ARGS = ["rcx", "rdx", "r8", "r9"]  # first 4 integer args


@dataclass
class EmulateResult:
    rax: int  # return value
    stopped: str  # why emulation stopped
    instructions: int


def emulate_pe_function(pe_path: str, symbol: str,
                        args: list[int] | None = None,
                        timeout_us: int = 1000000) -> EmulateResult:
    """Emulate a PE64 exported function under Unicorn.

    Sets up the x86-64 MS ABI calling convention (RCX, RDX, R8, R9 + shadow
    space) and runs the function in the Unicorn CPU emulator.

    Requires the `unicorn` package (`pip install unicorn`).
    """
    try:
        from unicorn import *
        from unicorn.x86_const import *
    except ImportError:
        raise RuntimeError(
            "unicorn is not installed — pip install unicorn (D4.2)")

    pe = load_pe(pe_path)
    if symbol not in pe.exports:
        raise KeyError(f"export {symbol!r} not found")

    rva = pe.exports[symbol]
    image_base = pe.image_base

    # read the binary to get the code bytes
    data = open(pe_path, "rb").read()

    # map the entire image at its preferred base
    total_size = 0
    for s in pe.sections:
        end = s["vaddr"] + s["vsize"]
        if end > total_size:
            total_size = end
    total_size = (total_size + 0xFFF) & ~0xFFF  # page align

    # initialize Unicorn x86-64 emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(image_base, total_size)
    mu.mem_write(image_base, data)

    # stack
    STACK_BASE = 0x7FF000000000
    STACK_SIZE = 0x100000  # 1 MB
    mu.mem_map(STACK_BASE - STACK_SIZE, STACK_SIZE)
    mu.reg_write(UC_X86_REG_RSP, STACK_BASE)

    # shadow space (32 bytes) + return address
    mu.reg_write(UC_X86_REG_RSP, STACK_BASE - 8)
    mu.mem_write(STACK_BASE - 8, struct.pack("<Q", 0xDEADBEEF))  # fake return addr

    # set MS ABI args
    args = args or []
    for i, val in enumerate(args[:4]):
        mu.reg_write(getattr(uc_x86_const, f"UC_X86_REG_{REG_ARGS[i].upper()}"), val)

    # start execution at the function's RVA
    start_addr = image_base + rva
    mu.emu_start(start_addr, 0, timeout=timeout_us)

    rax = mu.reg_read(UC_X86_REG_RAX)
    return EmulateResult(rax=rax, stopped="completed", instructions=0)
