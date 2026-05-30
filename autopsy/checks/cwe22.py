"""CWE-22: Path traversal (improper limitation of a pathname to a restricted directory).

Strategy (whole-program, call-site-driven): locate every call to a file-system
sink that accepts a pathname argument (``fopen``/``open``/``openat``/
``freopen``/``unlink``/``unlinkat``/``rename``/``stat``/``lstat``/``access``/
``readlink``/``opendir``/``mkdir``/``rmdir``/``chdir``). For each, confirm
that the program reads attacker-controlled input (``fgets``/``read``/``gets``/
``scanf``/``fread``/``recv``/``getenv``) AND that no path-sanitization helper
(``realpath``/``canonicalize_file_name``/``basename``) is present in the
program. The combination of an attacker-input source and a file-system path
sink with no canonicalization is the structural shape of the CWE-22 weakness
class — the most common path-traversal exploit shape is
``fopen(strcat("/var/www/", user_input))`` where ``user_input`` contains
``../../etc/passwd``.

Like CWE-78, this check is intentionally angr-free at the heuristic layer: the
``call_sites_to`` engine helper handles all call-graph discovery. The taint
trace records the input source program point and the sink program point.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Path-accepting filesystem sinks. A pathname argument flows into the kernel
# unchanged; if that pathname is attacker-controlled and not canonicalized,
# the caller can escape any intended directory prefix via ``../`` components.
_SINKS = {
    "fopen", "fopen64", "freopen",
    "open", "open64", "openat", "openat64", "creat",
    "unlink", "unlinkat", "remove",
    "rename", "renameat",
    "stat", "stat64", "lstat", "lstat64", "fstatat",
    "access", "faccessat",
    "readlink", "readlinkat",
    "opendir",
    "mkdir", "mkdirat", "rmdir",
    "chdir", "chroot",
    "symlink", "symlinkat", "link", "linkat",
    "truncate",
    "chmod", "lchmod", "fchmodat",
    "chown", "lchown", "fchownat",
}

# Functions that introduce attacker-controlled input. ``getenv`` is included
# (unlike the CWE-78 set) because a frequent path-traversal vector is
# ``fopen(getenv("HOME"))`` style code — environment is attacker-influenced on
# setuid binaries and untrusted child processes.
_SOURCES = {
    "fgets", "gets", "read", "scanf", "__isoc99_scanf",
    "fread", "recv", "recvfrom", "getline", "getenv", "secure_getenv",
}

# Path-canonicalization helpers. If the program calls any of these, we assume
# (conservatively) that the developer is sanitizing pathnames somewhere and we
# suppress the finding to preserve the zero-false-positive posture. This is
# weaker than a true def-use proof, but matches autopsy's heuristic posture
# (the user can re-audit suppressed binaries with ``--checks 22`` disabled).
_SANITIZERS = {"realpath", "canonicalize_file_name"}


def run(engine) -> list[Finding]:
    sink_calls = engine.call_sites_to(_SINKS)
    if not sink_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []
    # If the program canonicalizes paths anywhere, suppress to avoid false
    # positives on programs that handle path sanitization out-of-band.
    if engine.call_sites_to(_SANITIZERS):
        return []

    # Use the earliest discovered source as the taint origin for the trace —
    # matches CWE-134 (test_earliest_source_used_as_taint_origin) so traces are
    # stable across runs.
    src = min(source_calls, key=lambda c: c.call_address)
    findings: list[Finding] = []
    for sink in sink_calls:
        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled input read via {src.target_name}()",
            ),
            TaintPoint(
                sink.call_address,
                f"tainted data reaches filesystem path sink {sink.target_name}()",
            ),
        ]
        findings.append(
            Finding(
                cwe=22,
                function=sink.caller_function,
                address=sink.call_address,
                evidence=(
                    f"call to {sink.target_name}() in {sink.caller_function} "
                    f"with program input read via {src.target_name}() and no "
                    f"path canonicalization (realpath/canonicalize_file_name) "
                    f"observed in the binary"
                ),
                taint_trace=trace,
                confidence=_confidence(sink.target_name),
            )
        )
    return findings


def _confidence(sink_name: str) -> str:
    """Confidence for a CWE-22 finding.

    ``"medium"`` for the *destructive* or *state-changing* sinks (``unlink``,
    ``rename``, ``open``-for-write, ``chmod``, ``chown``, ``chroot``,
    ``truncate``, ``symlink``, ``link``, ``rmdir``, ``mkdir``) — a path-traversal
    bug here lets an attacker mutate filesystem state outside the intended
    directory, which is the classic critical-impact path-traversal exploit
    shape. ``"low"`` for *read-only* metadata sinks (``stat``/``lstat``/
    ``access``/``readlink``/``opendir``/``chdir``) where the attacker can
    observe but not modify — still a CWE-22 finding by MITRE's definition but
    a weaker triage signal, so the analyst can prioritize the high-impact
    sinks first.
    """
    state_changing = {
        "unlink", "unlinkat", "remove",
        "rename", "renameat",
        "open", "open64", "openat", "openat64", "creat",
        "fopen", "fopen64", "freopen",
        "chmod", "lchmod", "fchmodat",
        "chown", "lchown", "fchownat",
        "chroot",
        "truncate",
        "symlink", "symlinkat", "link", "linkat",
        "mkdir", "mkdirat", "rmdir",
    }
    return "medium" if sink_name in state_changing else "low"
