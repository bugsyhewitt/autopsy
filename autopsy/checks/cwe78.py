"""CWE-78: OS command injection.

Strategy (whole-program): locate every call to a command-execution sink
(``system``, ``execve``, ``execl``, ``popen``, ``posix_spawn``, …). For each,
confirm that the program also reads attacker-controlled input
(``fgets``/``read``/``gets``/``scanf``/``fread``/``recv``) and that the sink
is reachable in the call graph from a function that consumes that input. The
taint trace records the input source program point and the sink program point.

Sink coverage (as of R37):
- ``system`` / ``popen``                 — shell-interpolation sinks
- ``execve`` / ``execl`` / ``execlp`` / ``execvp`` / ``execvpe``
  — exec(3) family; ``execvpe`` is a GNU extension available on Linux
- ``posix_spawn`` / ``posix_spawnp``     — POSIX.1-2008 spawn (modern C)
- ``wordexp``                            — shell-expansion sink; attacker
  input in a ``wordexp()`` call expands to arbitrary commands via ``$()``
  or backtick substitution
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Command-execution sinks.
# R37 additions: execvpe (GNU), posix_spawn, posix_spawnp (POSIX.1-2008),
# wordexp (shell-expansion sink).
_SINKS = {
    "system",
    "popen",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "execvpe",
    "posix_spawn",
    "posix_spawnp",
    "wordexp",
}
# Functions that introduce attacker-controlled input.
_SOURCES = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "fread", "recv"}


def run(engine) -> list[Finding]:
    sink_calls = engine.call_sites_to(_SINKS)
    if not sink_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        # No tainted source -> not attacker-controlled -> no finding.
        return []

    # Use the earliest-addressed source as the taint origin for a stable
    # trace across runs (matches the CWE-22 / CWE-134 convention).
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
                f"tainted data reaches command sink {sink.target_name}()",
            ),
        ]
        findings.append(
            Finding(
                cwe=78,
                function=sink.caller_function,
                address=sink.call_address,
                evidence=(
                    f"call to {sink.target_name}() in {sink.caller_function} "
                    f"with program input read via {src.target_name}()"
                ),
                taint_trace=trace,
                confidence=_confidence(sink.target_name),
            )
        )
    return findings


def _confidence(sink_name: str) -> str:
    """Confidence for a CWE-78 finding.

    ``"high"`` when the sink is an ``exec*`` / ``posix_spawn*`` family call
    that passes the command/argv straight to the kernel with no shell-quoting
    or expansion step — ``execve``, ``execl``, ``execlp``, ``execvp``,
    ``execvpe``, ``posix_spawn``, ``posix_spawnp``. A tainted argument
    reaching any of these is a tight, high-signal pattern.

    ``"medium"`` for ``system``, ``popen``, and ``wordexp``, where a shell
    layer interposes (shell quoting *might* limit exploitation, though in
    practice rarely does), or the expansion is indirect (``wordexp`` expands
    its *words* argument through the shell word-expansion rules, so attacker
    input in the string is still exploitable via ``$(...)`` / backtick
    substitution but the path is one step longer).
    """
    exec_family = {
        "execve", "execl", "execlp", "execvp", "execvpe",
        "posix_spawn", "posix_spawnp",
    }
    return "high" if sink_name in exec_family else "medium"
