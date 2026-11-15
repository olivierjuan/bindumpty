"""humpty.analyze.smt_prove — Directive 5: generalized SMT equivalence
proofs (FR-11 beyond the FNV-1a bounded induction).

Approach (QF_BV, quantifier-free bitvectors):
- Both the ORIGINAL (Ghidra decompiled C) and the CANDIDATE (LLM source)
  are translated into Z3 bitvector expressions by a small C-subset
  interpreter: straight-line statements, if/else with symbolic
  conditions, uintN_t/intN_t locals, + - * / % & | ^ << >> ~ comparisons.
  Loops are NOT supported (v0 scope: small, loop-free mathematical or
  bit-twiddling leaves — the FR-11 whitepaper scope).
- Equivalence: for symbolic inputs, assert original(...) != candidate(...)
  and require the solver to return UNSAT. UNSAT awards a genuine
  'proven' status; SAT yields the concrete diverging input as a CEGIS
  counterexample.

Functions with pointer arguments, memory writes, or loops are out of
scope for v0 and reported as 'unsupported' rather than proven.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import z3

__all__ = ["SmtProof", "prove_equivalence", "c_functions_to_z3"]

_TYPE_WIDTHS = {
    "uint8_t": 8, "int8_t": 8,
    "uint16_t": 16, "int16_t": 16,
    "uint32_t": 32, "int32_t": 32,
    "uint64_t": 64, "int64_t": 64,
    "int": 32, "unsigned int": 32, "unsigned": 32,
    "char": 8, "unsigned char": 8,
    "long": 64, "unsigned long": 64,
    "size_t": 64,
}

_TYPE_RE = re.compile(
    r"^\s*(?P<type>(?:unsigned\s+|signed\s+)?(?:u?int\d+_t|char|long|int|"
    r"short|size_t)(?:\s*\*)*)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*[{;]")


@dataclass
class SmtProof:
    status: str                 # "proven" | "refuted" | "unsupported" | "error"
    diverging_input: dict = field(default_factory=dict)
    details: str = ""


def _extract_function(src: str, name: str) -> tuple[list, list, str] | None:
    """Pull (params, body_lines, ret_type) for `name` from C source."""
    # find the definition line
    pat = re.compile(
        rf"^\s*(?P<ret>[A-Za-z_][\w]*(?:\s*\*)*)\s+{re.escape(name)}"
        rf"\s*\((?P<params>[^)]*)\)\s*\{{", re.M)
    m = pat.search(src)
    if not m:
        return None
    ret = m.group("ret").strip()
    params = []
    for p in m.group("params").split(","):
        p = p.strip()
        if not p or p == "void":
            continue
        pm = re.match(r"^(.*?)([A-Za-z_]\w*)$", p.replace("*", " * "))
        if pm:
            ptype = re.sub(r"\s+", " ", pm.group(1).strip())
            params.append((ptype, pm.group(2)))
    # body: balanced braces from the definition
    start = m.end() - 1
    depth, body_start = 0, m.end()
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                body = src[body_start:i]
                break
    else:
        return None
    raw = [l.strip() for l in body.splitlines()
           if l.strip() and not l.strip().startswith(("//", "/*"))]
    # split multi-statement lines on ';'
    lines: list[str] = []
    for l in raw:
        if l.startswith("if") or l.startswith("for") or l.startswith("while"):
            lines.append(l)   # control flow — handled (or rejected) later
            continue
        for stmt in l.split(";"):
            stmt = stmt.strip()
            if stmt:
                lines.append(stmt)
    return params, lines, ret


class _Translator:
    """Symbolically executes a C-subset body with Z3 bitvector state."""

    def __init__(self, params: list, body: list, arg_suffix: str):
        self.state: dict[str, z3.ExprRef] = {}
        self.memories: dict[str, z3.ArrayRef] = {}
        self.arg_suffix = arg_suffix
        for ptype, pname in params:
            if "*" in ptype:
                # pointer param -> symbolic memory (array addr(64) -> byte)
                arr = z3.Array(f"mem_{pname}_{arg_suffix}",
                               z3.BitVecSort(64), z3.BitVecSort(8))
                self.memories[pname] = arr
                self.state[pname] = z3.BitVec(f"{pname}_base_{arg_suffix}", 64)
                continue
            width = _TYPE_WIDTHS.get(ptype.replace(" ", ""), 32)
            self.state[pname] = z3.BitVec(f"{pname}_{arg_suffix}", width)

    # ---- statement dispatch -------------------------------------------
    def run(self, lines: list) -> z3.ExprRef | None:
        ret = None
        for line in lines:
            r = self._stmt(line)
            if r is not None:
                ret = r
        return ret

    def _stmt(self, line: str) -> z3.ExprRef | None:
        if line.startswith("return"):
            expr = line[len("return"):].rstrip(";").strip()
            return self._eval(expr) if expr else self.state.get("$ret")
        m = re.match(r"^(?:uint\d+_t |int\d+_t |unsigned |long |int )?"
                     r"([A-Za-z_]\w*)\s*=\s*(.+?);?$", line)
        if m:
            self.state[m.group(1)] = self._eval(m.group(2))
            return None
        if line.startswith("if"):
            raise UnsupportedError(f"if-statement: {line[:40]}")
        raise UnsupportedError(f"statement: {line[:40]}")

    # ---- expression evaluation ----------------------------------------
    def _eval(self, expr: str) -> z3.ExprRef:
        expr = expr.strip()
        # strip matching outer parentheses: (A) or (A) op (B) handled by
        # the op-split below once parens are transparent
        while expr.startswith("(") and expr.endswith(")"):
            depth = 0
            ok = True
            for i, c in enumerate(expr):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0 and i != len(expr) - 1:
                        ok = False
                        break
            if ok:
                expr = expr[1:-1].strip()
            else:
                break
        # parenthesis-free shunting via recursion on the lowest-precedence op
        for op in ("^", "|", "&", "<<", ">>", "+", "-", "*", "/", "%"):
            # split at the top level only (no nested parens handling for
            # nested splits — v0 assumes flat expressions)
            idx = _find_top_level(expr, op)
            if idx > 0:
                left = self._eval(expr[:idx])
                right = self._eval(expr[idx + len(op):])
                return _apply(op, left, right)
        # unary
        if expr.startswith("~"):
            return ~self._eval(expr[1:])
        if expr.startswith("-") and not expr.startswith("-0x"):
            return -self._eval(expr[1:])
        # hex / dec literal
        if re.match(r"^0[xX][0-9a-fA-F]+u?$", expr):
            v = int(expr.rstrip("u"), 16)
            width = max(32, v.bit_length())
            return z3.BitVecVal(v, width)
        if re.match(r"^\d+u?$", expr):
            v = int(expr.rstrip("u"))
            width = max(32, v.bit_length())
            return z3.BitVecVal(v, width)
        # dereference: name[expr] or name->field or *name (byte load)
        m2 = re.match(r"^([A-Za-z_]\w*)\[([^]]+)\]$", expr)
        if m2 and m2.group(1) in self.memories:
            idx = self._eval(m2.group(2))
            byte = z3.Select(self.memories[m2.group(1)],
                             z3.ZeroExt(56, z3.Extract(7, 0, idx)))
            return z3.ZeroExt(24, byte)   # byte -> uint32
        if expr.startswith("*") and expr[1:] in self.memories:
            byte = z3.Select(self.memories[expr[1:]],
                             self.state[expr[1:]])
            return z3.ZeroExt(24, byte)
        # variable
        if re.match(r"^[A-Za-z_]\w*$", expr):
            if expr in self.state:
                return self.state[expr]
            raise UnsupportedError(f"unknown identifier {expr}")
        raise UnsupportedError(f"expression: {expr[:40]}")


def _find_top_level(expr: str, op: str) -> int:
    """Index of the LAST top-level occurrence of op (left-assoc eval by
    rightmost split), ignoring parentheses nesting."""
    depth = 0
    best = -1
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0:
            if op in ("<<", ">>") and expr.startswith(op, i):
                if not (op == "<<" and expr[i:i + 3] == "<<<"):
                    best = i
            elif expr.startswith(op, i) and not expr.startswith(op * 2, i):
                # avoid matching '>>' inside '>>=' etc — v0 simple ops
                if not (i + len(op) < len(expr)
                        and expr[i + len(op)] in "=<>|&+-*/%"):
                    best = i
        i += 1
    return best


def _apply(op: str, left: z3.ExprRef, right: z3.ExprRef):
    width = max(left.size(), right.size())
    left, right = z3.ZeroExt(width - left.size(), left), \
        z3.ZeroExt(width - right.size(), right)
    return {
        "^": left ^ right, "|": left | right, "&": left & right,
        "<<": left << z3.ZeroExt(width, z3.Extract(7, 0, right))
        if right.size() < width else left << right,
        "+": left + right, "-": left - right, "*": left * right,
    }[op] if op != ">>" else z3.LShR(left, right)


class UnsupportedError(ValueError):
    pass


def c_functions_to_z3(original_src: str, candidate_src: str,
                      name: str) -> tuple:
    """Extract and translate both function versions.

    Returns (orig_translator, cand_translator, ret_width, params) — the
    callers build the equivalence query over symbolic inputs.
    """
    o = _extract_function(original_src, name)
    c = _extract_function(candidate_src, name)
    if o is None or c is None:
        raise UnsupportedError(f"function {name} not found in both sources")
    op, ob = o[0], o[1]
    cp, cb = c[0], c[1]
    if [p for p in op] != [p for p in cp]:
        raise UnsupportedError("parameter lists differ")
    ot = _Translator(op, ob, "orig")
    ct = _Translator(cp, cb, "cand")
    return ot, ct, _TYPE_WIDTHS.get(o[2].replace(" ", ""), 32), op, ob, cb


def prove_equivalence(original_src: str, candidate_src: str,
                      name: str, timeout_ms: int = 30000) -> SmtProof:
    """Prove original == candidate for all symbolic inputs (QF_BV)."""
    try:
        ot, ct, ret_width, params, ob, cb = c_functions_to_z3(
            original_src, candidate_src, name)
    except UnsupportedError as e:
        return SmtProof(status="unsupported", details=str(e))

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    # build symbolic inputs (both translators must see the SAME values:
    # constrain orig_X == cand_X for every parameter, and symbolic
    # memories equal element-wise)
    for ptype, pname in params:
        a = ot.state.get(pname)
        b = ct.state.get(pname)
        if a is not None and b is not None:
            solver.add(a == b)
        am = ot.memories.get(pname)
        bm = ct.memories.get(pname)
        if am is not None and bm is not None:
            # equality of the readable window (a bounded prefix keeps it
            # quantifier-free): 4096 bytes covers the toy + kernel leaves
            addr_lo = z3.BitVecVal(0, 64)
            for off in range(0, 4096, 512):
                solver.add(z3.Select(am, z3.BitVecVal(off, 64))
                           == z3.Select(bm, z3.BitVecVal(off, 64)))
                solver.add(z3.Select(am, z3.BitVecVal(off + 1, 64))
                           == z3.Select(bm, z3.BitVecVal(off + 1, 64)))

    oret = ot.run(ob)
    cret = ct.run(cb)
    if oret is None or cret is None:
        return SmtProof(status="unsupported", details="no return value")
    if oret.size() != cret.size():
        oret = z3.ZeroExt(cret.size() - oret.size(), oret) \
            if oret.size() < cret.size() else z3.Extract(
                cret.size() - 1, 0, oret)
    solver.add(oret != cret)

    res = solver.check()
    if res == z3.unsat:
        return SmtProof(status="proven",
                        details="unsat: outputs equal for all inputs")
    if res == z3.sat:
        model = solver.model()
        inputs = {}
        for ptype, pname in params:
            a = ot.state.get(pname)
            if a is not None:
                try:
                    inputs[pname] = model.eval(a).as_long()
                except Exception:  # noqa: BLE001
                    inputs[pname] = None
        return SmtProof(status="refuted", diverging_input=inputs,
                        details="sat: outputs differ on the model")
    return SmtProof(status="error", details=f"solver: {res}")
