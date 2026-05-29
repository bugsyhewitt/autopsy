"""CWE-369: Divide By Zero.

Strategy (whole-program, register-level): locate every ``div``/``idiv``
instruction whose divisor is *not* guarded by a preceding zero-check, and report
it when the program also reads attacker-controlled input. On x86_64, ``div`` and
``idiv`` take a single explicit operand — the divisor — which is always a
register or memory location (there is no immediate divisor form). When that
divisor evaluates to zero the CPU raises a divide-error exception (#DE), which
the kernel delivers as ``SIGFPE`` and crashes the process. If an attacker can
drive the divisor to zero (the classic ``x / atoi(user_input)`` with no
``if (d == 0)`` check), that is the denial-of-service weakness CWE-369 names.

The engine helper :meth:`AngrEngine.divisions_with_unguarded_divisor` does the
disassembly-level work: it walks each function, finds the division instructions,
and excludes any whose divisor register is the subject of a ``cmp``/``test``
followed by a conditional branch before the divide — i.e. a guard like
``if (d == 0) return;``. Excluding guarded sites is what preserves autopsy's
zero-false-positive posture on well-written code: a program that checks its
divisor before dividing is not vulnerable and must not be flagged.

Like CWE-78/134/190, this check requires an attacker-controlled input source to
be present in the binary (``fgets``/``scanf``/``read``/``atoi``/``strtol`` …).
Without a source the unguarded divisor is a constant or internally-derived value
the attacker cannot influence, so flagging it would be a false positive. The
finding is reported at ``medium`` confidence: an unguarded divisor co-located
with an input source is a strong structural signal, but the check does not prove
a register-level def-use chain from the specific input read to the divisor.

x86_64 only: the divisor-register reasoning relies on x86_64 disassembly. The
engine returns an empty list on other architectures, so on AArch64 this check
yields no findings (it is excluded from the architecture-agnostic set and
skipped upstream).
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Attacker-controlled input sources. A divisor the program never sourced from
# input cannot be driven to zero by an attacker, so an input source must be
# present for an unguarded division to be a CWE-369 concern. This mirrors the
# source set used by CWE-190.
_SOURCES = {
    "fgets",
    "gets",
    "read",
    "scanf",
    "__isoc99_scanf",
    "fscanf",
    "__isoc99_fscanf",
    "sscanf",
    "__isoc99_sscanf",
    "atoi",
    "atol",
    "atoll",
    "strtol",
    "strtoul",
    "strtoll",
}


def run(engine) -> list[Finding]:
    divisions = engine.divisions_with_unguarded_divisor()
    if not divisions:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        # No attacker-controlled input: an unguarded divisor is internally
        # derived and not a CWE-369 concern.
        return []

    src = source_calls[0]
    findings: list[Finding] = []
    for div in divisions:
        evidence = (
            f"unguarded integer division (divisor {div['divisor']}) in "
            f"{div['function']} with no zero-check; attacker input via "
            f"{src.target_name}() can drive the divisor to zero (SIGFPE)"
        )
        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled value introduced via {src.target_name}()",
            ),
            TaintPoint(
                div["address"],
                f"division with unguarded divisor {div['divisor']} (no zero-check)",
            ),
        ]
        findings.append(
            Finding(
                cwe=369,
                function=div["function"],
                address=div["address"],
                evidence=evidence,
                taint_trace=trace,
                # Strong structural signal (unguarded divisor + input source
                # present) but no proven register-level def-use chain from the
                # specific read to the divisor -> medium.
                confidence="medium",
            )
        )
    return findings
