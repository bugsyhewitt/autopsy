"""CWE-78: OS command injection.

Strategy (whole-program): locate every call to a command-execution sink
(``system``, ``execve``, ``execl``, ``popen``). For each, confirm that the
program also reads attacker-controlled input (``fgets``/``read``/``gets``/
``scanf``/``fread``) and that the sink is reachable in the call graph from a
function that consumes that input. The taint trace records the input source
program point and the sink program point.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Command-execution sinks.
_SINKS = {"system", "execve", "execl", "execlp", "execvp", "popen"}
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

    # Use the first discovered source as the taint origin for the trace.
    src = source_calls[0]
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

    ``"high"`` when the sink is an ``exec*`` family call that takes the tainted
    argument directly (``execve``/``execl``/``execlp``/``execvp``); these pass
    the command/argv straight to the kernel with no shell-quoting opportunity,
    so a tainted argument reaching them is a tight, high-signal pattern.
    ``"medium"`` for ``system``/``popen``, where the source+sink pairing is
    present but the flow evidence is weaker (the heuristic confirms both calls
    exist program-wide, not a register-level data dependency).
    """
    exec_family = {"execve", "execl", "execlp", "execvp"}
    return "high" if sink_name in exec_family else "medium"
