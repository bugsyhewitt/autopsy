"""CWE-190: integer overflow propagating into an allocator size argument.

Strategy (whole-program): locate every call to an allocator (``malloc``,
``calloc``, ``realloc``). For each, scan the basic block(s) leading up to the
call within the same function for an arithmetic operation (``imul``/``mul``/
``add``/``shl``/``lea`` with scale) that computes the size in a 32-bit
register (``e**`` registers, which truncate/overflow). If the program also
reads attacker-controlled input, the computed size is tainted and may overflow.
The taint trace records input source, the arithmetic op, and the allocator call.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

_ALLOCATORS = {"malloc", "calloc", "realloc", "reallocarray"}
_SOURCES = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}
# Arithmetic mnemonics that can overflow when producing a size.
_ARITH = {"imul", "mul", "add", "shl", "sal", "lea"}
# 32-bit registers whose results truncate to 32 bits (overflow surface).
_E_REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "r8d", "r9d", "r10d", "r11d")


def run(engine) -> list[Finding]:
    alloc_calls = engine.call_sites_to(_ALLOCATORS)
    if not alloc_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []

    cfg = engine.cfg()
    findings: list[Finding] = []
    src = source_calls[0]

    for call in alloc_calls:
        arith = _arith_before_call(engine, cfg, call)
        if arith is None:
            continue
        arith_addr, arith_mnemonic = arith
        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled value introduced via {src.target_name}()",
            ),
            TaintPoint(
                arith_addr,
                f"32-bit arithmetic ({arith_mnemonic}) computes allocation size (overflow surface)",
            ),
            TaintPoint(
                call.call_address,
                f"computed size passed to {call.target_name}()",
            ),
        ]
        findings.append(
            Finding(
                cwe=190,
                function=call.caller_function,
                address=call.call_address,
                evidence=(
                    f"{arith_mnemonic} producing a 32-bit size feeds "
                    f"{call.target_name}() in {call.caller_function}"
                ),
                taint_trace=trace,
            )
        )
    return findings


def _arith_before_call(engine, cfg, call):
    """Return (addr, mnemonic) of the last overflow-prone 32-bit arithmetic op
    in the basic block containing ``call``, or None if there is none."""
    func = cfg.kb.functions.get(call.caller_function)
    if func is None:
        # Fall back to searching by address.
        func = cfg.kb.functions.floor_func(call.call_address)
    if func is None:
        return None
    candidate = None
    for block in func.blocks:
        try:
            insns = block.capstone.insns
        except Exception:  # pragma: no cover - defensive
            continue
        for insn in insns:
            if insn.address >= call.call_address:
                continue
            if insn.mnemonic in _ARITH and any(
                reg in insn.op_str for reg in _E_REGS
            ):
                candidate = (insn.address, insn.mnemonic)
    return candidate
