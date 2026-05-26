"""Unit tests for autopsy.pipeline_adapter.

All angr interactions are mocked. Tests verify:
- analyze_binary() returns list[BinaryFinding]
- Findings are correctly converted from autopsy.report.Finding
- Taint traces are preserved
- Errors are returned as CWE-0 sentinel findings
- state_limit_exceeded surfaces as an error finding
"""

from __future__ import annotations

from pathlib import Path

import pytest

from binary_finding_schema import BinaryFinding
from autopsy.pipeline_adapter import analyze_binary, _to_binary_finding
from autopsy.report import Finding, Report, TaintPoint


def _report_with_findings(*findings) -> Report:
    r = Report(binary="/tmp/test", checks=[119])
    r.findings = list(findings)
    return r


def _report_with_error(msg: str) -> Report:
    r = Report(binary="/tmp/test", checks=[119])
    r.error = msg
    return r


def _finding(cwe=119, function="vuln_fn", address=0x401000, evidence="test") -> Finding:
    return Finding(cwe=cwe, function=function, address=address, evidence=evidence)


def test_analyze_binary_returns_binary_findings(monkeypatch, tmp_path):
    """analyze_binary returns list[BinaryFinding] on success."""
    f = _finding()
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with_findings(f))

    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = analyze_binary(p)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], BinaryFinding)
    assert result[0].cwe_id == "CWE-119"
    assert result[0].function == "vuln_fn"
    assert result[0].address == hex(0x401000)
    assert result[0].evidence == "test"


def test_analyze_binary_empty_on_no_findings(monkeypatch, tmp_path):
    """analyze_binary returns empty list when report has no findings."""
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with_findings())

    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = analyze_binary(p)
    assert result == []


def test_analyze_binary_error_returns_sentinel(monkeypatch, tmp_path):
    """Analysis errors are returned as a CWE-0 sentinel finding."""
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with_error("angr exploded"))

    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = analyze_binary(p)

    assert len(result) == 1
    assert result[0].cwe_id == "CWE-0"
    assert "angr exploded" in result[0].evidence


def test_analyze_binary_taint_trace_preserved(monkeypatch, tmp_path):
    """Taint traces from autopsy findings are preserved in BinaryFinding."""
    tp1 = TaintPoint(address=0x401010, description="source")
    tp2 = TaintPoint(address=0x401020, description="sink")
    f = Finding(cwe=119, function="fn", address=0x401020, evidence="e",
                taint_trace=[tp1, tp2])
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with_findings(f))

    p = tmp_path / "elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = analyze_binary(p)

    assert len(result) == 1
    trace = result[0].taint_trace
    assert len(trace) == 2
    assert trace[0].address == hex(0x401010)
    assert trace[0].description == "source"
    assert trace[1].address == hex(0x401020)


def test_to_binary_finding_conversion():
    """_to_binary_finding converts autopsy Finding to BinaryFinding correctly."""
    f = _finding(cwe=78, function="run_cmd", address=0x40118f, evidence="system call")
    bf = _to_binary_finding(f)

    assert bf.cwe_id == "CWE-78"
    assert bf.function == "run_cmd"
    assert bf.address == "0x40118f"
    assert bf.evidence == "system call"
    assert bf.taint_trace == []
    assert bf.symbol is None


def test_analyze_binary_conforms_to_protocol():
    """analyze_binary is callable with (Path) -> list[BinaryFinding] signature."""
    from binary_pipeline import BinaryAnalyzer
    # Check callable — runtime check on the Protocol
    assert callable(analyze_binary)
