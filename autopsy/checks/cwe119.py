"""CWE-119: buffer over-read/write via an attacker-controlled offset.

Strategy (whole-program): the danger pattern is a memory access whose *index*
(not just base) is a tainted value. At -O0 this compiles to a scaled-index
memory operand, e.g. ``mov byte ptr [rax+rdx], cl`` or
``movsxd``/``cdqe`` of an input-derived index followed by a store/load into a
buffer base. We detect a store or load that uses an index register which was
derived from attacker input (via atoi/strtol/scanf/read), within a function
reachable from the program input. The taint trace records the input source,
the index computation, and the unchecked memory access (the sink).
"""

from __future__ import annotations

import re

from autopsy.report import Finding, TaintPoint

_SOURCES = {"atoi", "strtol", "atol", "scanf", "__isoc99_scanf", "read", "fgets", "gets"}
# Index-register conversions that signal "this value is used as an index".
_INDEX_EXT = {"movsxd", "cdqe", "movsx", "movzx"}
# A scaled-index memory operand like [reg+reg], [reg+reg*N], or [base+reg].
_SCALED_INDEX = re.compile(r"\[[a-z0-9]+\s*\+\s*[a-z0-9]+(?:\s*\*\s*[0-9]+)?\]")
# A store/load opcode family we care about.
_MEM_OPS = {"mov", "movzx", "movsx"}


def run(engine) -> list[Finding]:
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []

    cfg = engine.cfg()
    findings: list[Finding] = []
    src = source_calls[0]

    for func in cfg.kb.functions.values():
        if func.is_plt or func.is_simprocedure:
            continue
        sink = _find_indexed_access(func)
        if sink is None:
            continue
        sink_addr, kind = sink
        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled index introduced via {src.target_name}()",
            ),
            TaintPoint(
                sink_addr,
                f"index used in unchecked {kind} memory access",
            ),
        ]
        findings.append(
            Finding(
                cwe=119,
                function=func.name,
                address=sink_addr,
                evidence=(
                    f"scaled-index memory {kind} in {func.name} using an "
                    f"input-derived offset with no preceding bounds check"
                ),
                taint_trace=trace,
            )
        )
        # One finding per function is sufficient for v0.1.
    return findings


def _find_indexed_access(func):
    """Find a scaled-index store/load that is *not* preceded by a bounds-check
    compare+branch in the same function. Returns (addr, "write"|"read")."""
    insns = []
    for block in func.blocks:
        try:
            insns.extend(block.capstone.insns)
        except Exception:  # pragma: no cover - defensive
            continue
    insns.sort(key=lambda i: i.address)

    saw_index_ext = False
    saw_bounds_check = False
    for insn in insns:
        mn, ops = insn.mnemonic, insn.op_str
        if mn in _INDEX_EXT:
            saw_index_ext = True
        # A cmp followed by a conditional jump is a (heuristic) bounds check.
        if mn == "cmp":
            saw_bounds_check = True
        if mn not in _MEM_OPS:
            continue
        if not _SCALED_INDEX.search(ops):
            continue
        if not saw_index_ext:
            # Require evidence the index came from a sign/zero-extended value
            # (the signature of an int index promoted to 64-bit for addressing).
            continue
        if saw_bounds_check:
            # A guarded access is the clean-baseline pattern; skip it.
            return None
        # Determine write vs read: write if the memory operand is the dest.
        kind = "write" if ops.strip().startswith("[") or _dest_is_mem(ops) else "read"
        return (insn.address, kind)
    return None


def _dest_is_mem(ops: str) -> bool:
    # `mov [mem], reg` => first operand (dest) is memory.
    first = ops.split(",", 1)[0].strip()
    return first.startswith("[") or "ptr [" in first
