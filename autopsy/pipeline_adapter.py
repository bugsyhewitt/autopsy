"""Pipeline adapter: expose autopsy as a BinaryAnalyzer for binary-pipeline.

Wraps :func:`autopsy.analyzer.analyze` into the
:class:`~binary_pipeline.BinaryAnalyzer` protocol so embalmer (or any other
orchestrator using ``binary-pipeline``) can call autopsy as a Python-API
analyzer rather than through a subprocess.

Usage::

    from pathlib import Path
    from autopsy.pipeline_adapter import analyze_binary

    findings = analyze_binary(Path("/path/to/target"))
    # returns list[BinaryFinding] from binary-finding-schema

This module is angr-free at import time: angr is only loaded when
:func:`analyze_binary` is actually called.
"""

from __future__ import annotations

from pathlib import Path

from binary_finding_schema import BinaryFinding, TaintTrace


def analyze_binary(binary: Path) -> list[BinaryFinding]:
    """Analyze ``binary`` using autopsy and return canonical BinaryFindings.

    Implements the :class:`~binary_pipeline.BinaryAnalyzer` protocol:
    ``(Path) -> list[BinaryFinding]``.

    Runs all supported CWE checks (119, 190, 416, 78). Errors and
    ``state_limit_exceeded`` conditions are handled gracefully — a single
    BinaryFinding with ``cwe_id="CWE-0"`` and the error as ``evidence``
    is returned so the caller is informed without raising an exception.

    Args:
        binary: Path to the target ELF binary.

    Returns:
        List of :class:`~binary_finding_schema.BinaryFinding` objects.
        Empty list if no findings. Single error finding on analysis failure.
    """
    # Lazy import preserves the angr-free module top level.
    from autopsy.analyzer import analyze

    report = analyze(binary=str(binary), checks_token="all")

    if report.error and not report.findings:
        # Surface the error as a distinguished finding rather than silently
        # swallowing it. CWE-0 is not a real CWE; it signals a tool error.
        return [
            BinaryFinding(
                cwe_id="CWE-0",
                function="<autopsy>",
                address="0x0",
                evidence=f"autopsy analysis error: {report.error}",
            )
        ]

    return [_to_binary_finding(f) for f in report.findings]


def _to_binary_finding(finding) -> BinaryFinding:
    """Convert an autopsy :class:`~autopsy.report.Finding` to a BinaryFinding.

    Preserves the taint trace if present.
    """
    trace = [
        TaintTrace(address=hex(tp.address), description=tp.description)
        for tp in finding.taint_trace
    ]
    return BinaryFinding(
        cwe_id=f"CWE-{finding.cwe}",
        function=finding.function,
        address=hex(finding.address),
        evidence=finding.evidence,
        taint_trace=trace,
    )
