"""CWE-134: Use of Externally-Controlled Format String.

Strategy (whole-program): locate every call to a printf-family format sink
(``printf``/``fprintf``/``sprintf``/``snprintf``/``syslog`` and the ``v*``
variants) whose *format-string* argument is NOT a compile-time string literal —
i.e. the format register is reloaded from a stack slot (a spilled function
parameter, or a value loaded from the heap / another variable) rather than set
to a constant ``.rodata`` pointer via ``lea reg, [rip + disp]``. The classic
pattern is ``printf(user_input)`` where ``user_input`` is a function argument
or a buffer that was filled from attacker-controlled input.

A finding requires both halves of the data flow:

  1. A printf-family sink whose format argument is non-literal (the structural
     half — detected by
     :meth:`AngrEngine.format_string_sinks_with_nonliteral_format`), and
  2. At least one attacker-controlled input source in the program (the taint
     half — the same ``_SOURCES`` set used by CWE-78), so the non-literal
     format can plausibly carry attacker data.

If the format is a string literal (the overwhelmingly common, safe case) the
engine helper does not report the sink, so this check never fires on benign
``printf("hello %s\n", name)`` style code. If there is no input source in the
program at all, the non-literal format cannot be attacker-controlled, so no
finding is emitted either.

Confidence rationale:
  ``"medium"`` — the non-literal format register sourced from a stack slot is a
  tight structural signal (a string-literal format would have been a
  ``lea``/immediate, which the engine excludes), and the presence of an input
  source confirms attacker data exists in the program. But this analysis does
  not prove a *register-level* def-use chain from the specific input read to
  the specific format slot, so it is medium rather than high. Full VEX-IR taint
  from source to the format slot is a post-v0.1 direction.

Architecture support:
  x86_64 (AMD64) and AArch64 (ARM64). The detection is arch-agnostic at the
  check level — it delegates the structural half to the arch-aware engine helper
  :meth:`AngrEngine.format_string_sinks_with_nonliteral_format`, which reads the
  format-string argument out of the per-architecture calling-convention register
  (SysV ``rdi``/``rsi``/``rdx`` on x86_64; AAPCS64 ``x0``/``x1``/``x2`` on
  AArch64) and recognizes both the x86_64 rodata-literal form (``lea reg,
  [rip+disp]``) and the AArch64 one (``adrp``/``adr``). ``call_sites_to`` (used
  for the input source) is already arch-aware.

[Worker decision: non-literal-format + global-source heuristic] Proving that
the exact bytes read by ``fgets`` reach the exact format slot would require the
VEX-IR def-use analysis listed as a Tier 3 post-v0.1 direction. The
non-literal-format detection (format register reloaded from a stack slot, never
a ``lea`` rodata pointer) combined with a program-wide input source matches the
real-world ``printf(user_controlled)`` pattern and holds the zero-false-positive
line on the clean baseline (whose only ``printf`` uses a literal format).
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Functions that introduce attacker-controlled input (same set as CWE-78).
_SOURCES = {
    "fgets",
    "gets",
    "read",
    "scanf",
    "__isoc99_scanf",
    "fread",
    "recv",
    "fscanf",
    "__isoc99_fscanf",
    "getenv",
}


def run(engine) -> list[Finding]:
    """Detect printf-family calls with an attacker-controllable format string.

    Returns one finding per printf-family sink whose format-string argument is
    non-literal, provided the program also reads attacker-controlled input.
    """
    sinks_fn = getattr(engine, "format_string_sinks_with_nonliteral_format", None)
    if not callable(sinks_fn):
        return []
    sinks = sinks_fn()
    if not sinks:
        return []

    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        # No tainted source in the program -> the non-literal format cannot be
        # attacker-controlled -> no finding.
        return []

    # Use the earliest input source as the taint origin for the trace.
    src = min(source_calls, key=lambda c: c.call_address)

    findings: list[Finding] = []
    for sink in sinks:
        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled input read via {src.target_name}()",
            ),
            TaintPoint(
                sink["call_address"],
                f"non-literal format string ({sink['fmt_reg']} reloaded from "
                f"stack slot {sink['fmt_slot']}) reaches {sink['sink_name']}()",
            ),
        ]
        findings.append(
            Finding(
                cwe=134,
                function=sink["function"],
                address=sink["call_address"],
                evidence=(
                    f"{sink['sink_name']}() in {sink['function']} called with a "
                    f"non-literal format string (format argument {sink['fmt_reg']} "
                    f"loaded from {sink['fmt_slot']}, not a constant) while the "
                    f"program reads input via {src.target_name}() — "
                    f"externally-controlled format string"
                ),
                taint_trace=trace,
                confidence="medium",
            )
        )
    return findings
