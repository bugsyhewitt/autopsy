"""Unit tests for the SARIF 2.1.0 emitter. angr-free."""

from __future__ import annotations

import json

import pytest

from autopsy.report import Finding, Report, TaintPoint
from autopsy.sarif import to_sarif, to_sarif_json


def _make_report(findings=None, checks=None, error=None):
    r = Report(
        binary="/tmp/test-binary",
        checks=checks or [119],
        max_states=1000,
        error=error,
    )
    if findings is not None:
        r.findings = findings
    return r


def _finding(cwe=119, fn="vuln_fn", addr=0x401140, evidence="overflow", trace=None,
             confidence="medium"):
    if trace is None:
        trace = [TaintPoint(0x401120, "tainted source"), TaintPoint(addr, "sink")]
    return Finding(cwe=cwe, function=fn, address=addr, evidence=evidence,
                   taint_trace=trace, confidence=confidence)


# --- Schema structure ---


def test_sarif_top_level_keys():
    sarif = to_sarif(_make_report())
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1
    assert "taxonomies" in sarif


def test_sarif_run_has_tool_and_results():
    sarif = to_sarif(_make_report())
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert run["tool"]["driver"]["name"] == "autopsy"


def test_sarif_empty_findings_zero_results():
    sarif = to_sarif(_make_report(findings=[]))
    assert sarif["runs"][0]["results"] == []


# --- Rules ---


def test_rules_include_requested_checks():
    sarif = to_sarif(_make_report(checks=[119, 190]))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "CWE-119" in rule_ids
    assert "CWE-190" in rule_ids


def test_rules_include_finding_cwes_not_in_checks():
    # A finding CWE that wasn't in the checks list should still produce a rule.
    f = _finding(cwe=415)
    sarif = to_sarif(_make_report(findings=[f], checks=[416]))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert "CWE-415" in rule_ids
    assert "CWE-416" in rule_ids


def test_rule_has_required_fields():
    sarif = to_sarif(_make_report(checks=[119]))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CWE-119"
    assert "shortDescription" in rule
    assert "fullDescription" in rule
    assert "helpUri" in rule
    assert rule["helpUri"].startswith("https://cwe.mitre.org/")


# --- Results ---


def test_result_maps_to_finding():
    f = _finding(cwe=416, fn="do_free", addr=0x401200, evidence="double use")
    sarif = to_sarif(_make_report(findings=[f], checks=[416]))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-416"
    assert result["message"]["text"] == "double use"


def test_result_location_has_absolute_address():
    addr = 0x4011aa
    f = _finding(addr=addr)
    sarif = to_sarif(_make_report(findings=[f]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["address"]["absoluteAddress"] == addr


def test_result_logical_location_has_function():
    f = _finding(fn="critical_fn")
    sarif = to_sarif(_make_report(findings=[f]))
    logical = sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert logical["name"] == "critical_fn"
    assert logical["kind"] == "function"


def test_result_taxa_references_cwe():
    f = _finding(cwe=78)
    sarif = to_sarif(_make_report(findings=[f], checks=[78]))
    taxa = sarif["runs"][0]["results"][0]["taxa"]
    assert any(t["id"] == "78" for t in taxa)


# --- Confidence -> SARIF level mapping ---


def test_high_confidence_maps_to_error_level():
    f = _finding(confidence="high")
    sarif = to_sarif(_make_report(findings=[f]))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["confidence"] == "high"


def test_medium_confidence_maps_to_warning_level():
    f = _finding(confidence="medium")
    sarif = to_sarif(_make_report(findings=[f]))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "warning"
    assert result["properties"]["confidence"] == "medium"


def test_low_confidence_maps_to_note_level():
    f = _finding(confidence="low")
    sarif = to_sarif(_make_report(findings=[f]))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert result["properties"]["confidence"] == "low"


# --- Taint trace as relatedLocations ---


def test_taint_trace_becomes_related_locations():
    trace = [
        TaintPoint(0x401100, "source of taint"),
        TaintPoint(0x401150, "propagated through"),
        TaintPoint(0x401200, "sink"),
    ]
    f = _finding(trace=trace)
    sarif = to_sarif(_make_report(findings=[f]))
    related = sarif["runs"][0]["results"][0]["relatedLocations"]
    assert len(related) == 3
    assert related[0]["message"]["text"] == "source of taint"
    assert related[0]["physicalLocation"]["address"]["absoluteAddress"] == 0x401100
    assert related[2]["physicalLocation"]["address"]["absoluteAddress"] == 0x401200


def test_empty_taint_trace_no_related_locations():
    f = _finding(trace=[])
    sarif = to_sarif(_make_report(findings=[f]))
    result = sarif["runs"][0]["results"][0]
    assert "relatedLocations" not in result


# --- Multiple findings ---


def test_multiple_findings_all_in_results():
    findings = [
        _finding(cwe=119, addr=0x4010, evidence="buf1"),
        _finding(cwe=415, addr=0x4020, evidence="double-free"),
        _finding(cwe=416, addr=0x4030, evidence="use-after"),
    ]
    sarif = to_sarif(_make_report(findings=findings, checks=[119, 415, 416]))
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    rule_ids = [r["ruleId"] for r in results]
    assert "CWE-119" in rule_ids
    assert "CWE-415" in rule_ids
    assert "CWE-416" in rule_ids


# --- Invocations ---


def test_successful_invocation_flag():
    sarif = to_sarif(_make_report())
    inv = sarif["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True


def test_error_invocation_flag():
    sarif = to_sarif(_make_report(error="angr failed"))
    inv = sarif["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    notifs = inv["toolExecutionNotifications"]
    assert any("angr failed" in n["message"]["text"] for n in notifs)


# --- to_sarif_json round-trip ---


def test_to_sarif_json_is_valid_json():
    report = _make_report(findings=[_finding()])
    s = to_sarif_json(report)
    parsed = json.loads(s)
    assert parsed["version"] == "2.1.0"


def test_to_sarif_json_indented_by_default():
    report = _make_report(findings=[])
    s = to_sarif_json(report)
    # Default indent=2 means the JSON spans multiple lines.
    assert "\n" in s


# --- CLI integration (no angr) ---


def test_cli_sarif_format_produces_sarif(monkeypatch, capsys):
    from autopsy import cli
    from autopsy.report import Report

    fake = Report(binary="b", checks=[416], max_states=1000)
    fake.findings = [_finding(cwe=416, evidence="freed twice")]
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "416", "--format", "sarif"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"][0]["ruleId"] == "CWE-416"
