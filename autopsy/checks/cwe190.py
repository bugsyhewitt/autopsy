"""CWE-190: integer overflow propagating into an allocator size argument.

Strategy (whole-program): locate every call to an allocator (``malloc``,
``calloc``, ``realloc``). For each, scan the basic block(s) leading up to the
call within the same function for an arithmetic operation that computes the size
in a 32-bit register (which truncates/overflows). If the program also reads
attacker-controlled input, the computed size is tainted and may overflow. The
taint trace records input source, the arithmetic op, and the allocator call.

Architecture-aware. The size-arithmetic discovery is delegated to
:meth:`AngrEngine.size_arith_before_call`, which knows both the x86_64 forms
(``imul``/``mul``/``add``/``shl``/``sal``/``lea`` over the ``e**``/``r**d``
register views) and the AArch64 forms (``mul``/``madd``/``add``/``lsl`` over the
``w0..w30`` view — e.g. ``count * width`` lowers to ``mul w8, w8, w9`` and
``count * 4096`` to ``lsl w8, w8, #0xc``). The size register truncates to 32
bits on both, which is the integer-overflow surface. The check therefore runs on
both architectures; the engine helper returns nothing on any other.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

_ALLOCATORS = {"malloc", "calloc", "realloc", "reallocarray"}
_SOURCES = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}


def run(engine) -> list[Finding]:
    alloc_calls = engine.call_sites_to(_ALLOCATORS)
    if not alloc_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []

    findings: list[Finding] = []
    src = source_calls[0]

    for call in alloc_calls:
        arith = engine.size_arith_before_call(call)
        if arith is None:
            continue
        arith_addr, arith_mnemonic, two_reg_operands = arith
        # "high" when both arithmetic operands are registers (both potentially
        # carry tainted, data-dependent values that can overflow together);
        # "medium" when one operand is an immediate/scale constant, so only a
        # single value is symbolic.
        confidence = "high" if two_reg_operands else "medium"
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
                confidence=confidence,
            )
        )
    return findings
