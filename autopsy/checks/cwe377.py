"""CWE-377: Insecure Temporary File.

Strategy (whole-program, call-site-driven): flag every call to a libc
temporary-file function whose contract is inherently race-prone — one that
generates a temporary *name* and hands it back to the caller, leaving a
time-of-check-to-time-of-use (TOCTOU) window between the name's creation and
the caller's subsequent ``open``/``fopen``. An attacker who wins that race can
pre-create the path (often as a symlink) and hijack the file the program
believes it created. The canonical offenders are ``tmpnam``/``tmpnam_r``,
``tempnam`` and ``mktemp``: each returns a *path string* but performs no atomic
create-and-open, so the file does not exist (or is attacker-controlled) at the
moment the program opens it. The safe replacement — ``mkstemp`` (and
``mkostemp``/``tmpfile``) — atomically creates *and opens* the file with
``O_CREAT | O_EXCL``, closing the window; ``man tmpnam`` and ``man mktemp``
explicitly direct users to ``mkstemp`` for this reason, and both were marked
LEGACY / obsolescent by POSIX.

Like CWE-676 (and unlike the taint-flow checks CWE-78/134), CWE-377 needs no
attacker-input source: the weakness is the *use of the race-prone function
itself*. MITRE classifies CWE-377 as creation of a temporary file in an
insecure manner, independent of any proven exploit path. This makes the
detector fully call-site-driven and therefore architecture-agnostic: it
resolves direct calls by symbol name and never inspects registers, so it runs
on every architecture autopsy can load (x86_64 and AArch64).

The detector deliberately does *not* flag the atomic replacements
(``mkstemp``/``mkostemp``/``tmpfile``): those are the safe forms users are told
to migrate to, and flagging them would defeat the zero-false-positive guarantee
on well-written code.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Race-prone libc temporary-file functions, mapped to the terse reason they are
# insecure and the atomic replacement users should migrate to. Keys are the
# symbol names that show up as direct-call targets in an ELF. The atomic
# create-and-open replacements (mkstemp/mkostemp/tmpfile) are intentionally
# absent — flagging them would be a false positive.
_INSECURE: dict[str, tuple[str, str]] = {
    # Returns a name with no atomic create; classic TOCTOU symlink race.
    "tmpnam": (
        "returns a temporary path without atomically creating the file, "
        "leaving a TOCTOU race before the caller opens it",
        "mkstemp",
    ),
    "tmpnam_r": (
        "returns a temporary path without atomically creating the file, "
        "leaving a TOCTOU race before the caller opens it",
        "mkstemp",
    ),
    # Honors TMPDIR but is otherwise identical to tmpnam's race.
    "tempnam": (
        "returns a temporary path without atomically creating the file, "
        "leaving a TOCTOU race before the caller opens it",
        "mkstemp",
    ),
    # Mutates a template in place to a name only; no create-and-open.
    "mktemp": (
        "expands a template to a name without creating the file, leaving a "
        "TOCTOU race before the caller opens it",
        "mkstemp",
    ),
}


def run(engine) -> list[Finding]:
    call_sites = engine.call_sites_to(set(_INSECURE))
    if not call_sites:
        return []
    findings: list[Finding] = []
    for cs in call_sites:
        reason, replacement = _INSECURE[cs.target_name]
        # All four functions share the same race-prone contract: the file is
        # never atomically created, so the TOCTOU window is structural, not a
        # heuristic guess. Medium confidence — the call is a definitive use of
        # a race-prone API, but autopsy does not prove the caller actually opens
        # the returned path (a program could, in principle, use the name for a
        # non-filesystem purpose).
        confidence = "medium"
        evidence = (
            f"call to insecure temporary-file function {cs.target_name}() in "
            f"{cs.caller_function}: {reason}; prefer {replacement}"
        )
        findings.append(
            Finding(
                cwe=377,
                function=cs.caller_function,
                address=cs.call_address,
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        cs.call_address,
                        f"insecure temporary-file creation via {cs.target_name}()",
                    )
                ],
                confidence=confidence,
            )
        )
    return findings
