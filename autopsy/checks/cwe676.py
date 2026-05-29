"""CWE-676: Use of Potentially Dangerous Function.

Strategy (whole-program, call-site-driven): flag every call to a libc function
that is inherently unsafe — one whose contract makes a memory-safety bug the
*default* outcome rather than a misuse. The canonical example is ``gets``,
which has no way to bound its write and was removed from C11 for exactly this
reason; the unbounded string family (``strcpy``/``strcat``/``sprintf`` and the
``vsprintf`` variant) and the unbounded scanners (``scanf``/``sscanf``/
``fscanf`` and their ``__isoc99_`` aliases) are in the same category: their
*bounded* siblings (``strncpy``/``strncat``/``snprintf``/``fgets``) exist
precisely to replace them.

Unlike the taint-flow checks (CWE-78/134), CWE-676 needs no attacker-input
source: the weakness is the *use of the function itself*. MITRE classifies
CWE-676 this way — it is a "use of a potentially dangerous function" regardless
of whether a specific tainted path has been proven. This makes the detector
fully call-site-driven and therefore architecture-agnostic: it resolves direct
calls by symbol name and never inspects registers, so it runs on every
architecture autopsy can load (x86_64 and AArch64).

The detector deliberately does *not* flag the bounded replacements
(``strncpy``/``strncat``/``snprintf``/``fgets``/``strlcpy``): those are the
safe forms users are told to migrate to, and flagging them would defeat the
zero-false-positive guarantee on well-written code (the clean-baseline fixture
uses ``strncpy``/``fgets`` and must stay silent).
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Inherently dangerous libc functions, mapped to the terse reason they are
# unsafe and the bounded replacement users should migrate to. Keys are the
# symbol names that show up as direct-call targets in an ELF (including the
# glibc ``__isoc99_`` scanf aliases). Bounded siblings (strncpy/snprintf/fgets)
# are intentionally absent — flagging them would be a false positive.
_DANGEROUS: dict[str, tuple[str, str]] = {
    # No bound is even expressible — removed from C11.
    "gets": ("no bounds check is possible; the call always risks overflow", "fgets"),
    # Unbounded string copy/concatenate.
    "strcpy": ("copies until NUL with no destination bound", "strncpy / strlcpy"),
    "strcat": ("concatenates until NUL with no destination bound", "strncat / strlcat"),
    # Unbounded formatted write.
    "sprintf": ("writes a formatted string with no destination bound", "snprintf"),
    "vsprintf": ("writes a formatted string with no destination bound", "vsnprintf"),
    # Unbounded scanners: a bare %s reads arbitrarily many bytes.
    "scanf": ("an unbounded %s conversion can overflow its target", "fgets + sscanf with widths"),
    "sscanf": ("an unbounded %s conversion can overflow its target", "sscanf with field widths"),
    "fscanf": ("an unbounded %s conversion can overflow its target", "fgets + sscanf with widths"),
    # glibc emits the scanf family under __isoc99_ aliases at -O0.
    "__isoc99_scanf": ("an unbounded %s conversion can overflow its target", "fgets + sscanf with widths"),
    "__isoc99_sscanf": ("an unbounded %s conversion can overflow its target", "sscanf with field widths"),
    "__isoc99_fscanf": ("an unbounded %s conversion can overflow its target", "fgets + sscanf with widths"),
}

# gets is the most dangerous of the set: it admits no safe usage at all, so a
# finding on it is high confidence. The others can in principle be used safely
# if the caller has already bounded the input, so they are medium confidence —
# the call is a strong structural red flag but not a proof of overflow.
_HIGH_CONFIDENCE = frozenset({"gets"})


def run(engine) -> list[Finding]:
    call_sites = engine.call_sites_to(set(_DANGEROUS))
    if not call_sites:
        return []
    findings: list[Finding] = []
    for cs in call_sites:
        reason, replacement = _DANGEROUS[cs.target_name]
        confidence = "high" if cs.target_name in _HIGH_CONFIDENCE else "medium"
        evidence = (
            f"call to dangerous function {cs.target_name}() in "
            f"{cs.caller_function}: {reason}; prefer {replacement}"
        )
        findings.append(
            Finding(
                cwe=676,
                function=cs.caller_function,
                address=cs.call_address,
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        cs.call_address,
                        f"use of potentially dangerous function {cs.target_name}()",
                    )
                ],
                confidence=confidence,
            )
        )
    return findings
