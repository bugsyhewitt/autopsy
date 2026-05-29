"""CWE-119: buffer over-read/write via an attacker-controlled offset.

Strategy (whole-program): the danger pattern is a memory access whose *index*
(not just base) is a tainted value. We detect a store or load that uses an
index register which was derived from attacker input (via atoi/strtol/scanf/
read), within a function reachable from the program input, and which is *not*
guarded by a preceding bounds-check compare/branch. The taint trace records the
input source, the index computation, and the unchecked memory access (the sink).

Architecture-aware. The two architectures express the same source-level
``buf[idx]`` access with different codegen at -O0:

* **x86_64 (AMD64).** The int index is sign/zero-extended to 64 bits
  (``movsxd``/``cdqe``/``movsx``/``movzx``) and folded into a scaled-index memory
  operand, e.g. ``mov byte ptr [rax+rdx], cl`` (base register + index register).
  The bounds check is a ``cmp`` followed by a conditional jump.

* **AArch64 (ARM64).** The int index is sign-extended with ``ldrsw xN,
  [slot]`` (load-and-sign-extend, the index reload) or ``sxtw xN, wM``, then the
  address is computed with an explicit ``add xD, xBase, xIdx`` (base register +
  index register) and dereferenced through that base register: ``str/ldr/strb/
  ldrb wN, [xD]``. There is no single scaled-index operand as on x86_64 — the
  scaling is materialized into ``xD``. The bounds check is a ``cmp``/``subs``/
  ``tst``/``tbz``/``tbnz``/``cbz``/``cbnz`` followed by a conditional branch
  (``b.<cond>``); a guarded access is the clean-baseline pattern and is skipped
  to preserve the zero-false-positive posture.

The arch-specific disassembly reasoning lives in the engine helper
:meth:`AngrEngine.indexed_memory_access_without_bounds_check`, which returns the
sink address, the access kind (read/write) and whether the offending access uses
a genuinely data-dependent register index (the "symbolic" case -> high
confidence, versus the static index-extension heuristic alone -> medium). The
helper returns nothing on architectures other than AMD64/AARCH64, so this check
is silent there.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

_SOURCES = {"atoi", "strtol", "atol", "scanf", "__isoc99_scanf", "read", "fgets", "gets"}


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
        sink = engine.indexed_memory_access_without_bounds_check(func)
        if sink is None:
            continue
        sink_addr, kind, symbolic_index = sink
        # "high" when the scaled-index operand uses a symbolic (register)
        # index — the offset is genuinely data-dependent. "medium" when the
        # detection rests on the static index-extension heuristic alone.
        confidence = "high" if symbolic_index else "medium"
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
                confidence=confidence,
            )
        )
        # One finding per function is sufficient for v0.1.
    return findings
