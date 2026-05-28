"""Fast unit tests for the argparse CLI. angr-free (analysis is monkeypatched)."""

import json

import pytest

from autopsy import cli
from autopsy.report import Report, Finding, TaintPoint


def test_help_lists_required_flags(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--binary" in out
    assert "--checks" in out
    assert "--max-states" in out
    assert "--format" in out
    # The choices for --checks must include all six tokens.
    for tok in ("119", "190", "415", "416", "78", "all"):
        assert tok in out


def test_checks_default_is_all():
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.checks == "all"
    assert args.max_states == 1000
    assert args.format == "json"


def test_format_sarif_accepted():
    args = cli.build_parser().parse_args(["--binary", "x", "--format", "sarif"])
    assert args.format == "sarif"


def test_binary_is_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--checks", "119"])


def test_main_prints_json_and_returns_zero(monkeypatch, capsys):
    fake = Report(binary="b", checks=[119], max_states=1000)
    fake.findings = [
        Finding(cwe=119, function="store_at", address=0x401140,
                evidence="oob", taint_trace=[TaintPoint(0x401120, "idx")]),
    ]
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "119"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["findings"][0]["cwe"] == 119


def test_main_state_limit_returns_two(monkeypatch, capsys):
    fake = Report(binary="b", checks=[119], max_states=10,
                  state_limit_exceeded=True, error="state limit exceeded (>10 states)")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "119", "--max-states", "10"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "state limit exceeded" in err


def test_main_notes_skipped_checks_on_stderr(monkeypatch, capsys):
    fake = Report(binary="b", checks=[119, 78], max_states=1000)
    fake.skipped_checks = [119]
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "all"])
    assert rc == 0
    captured = capsys.readouterr()
    # stdout stays machine-clean JSON; the note goes to stderr.
    json.loads(captured.out)
    assert "CWE-119" in captured.err
    assert "architecture" in captured.err


def test_main_engine_error_returns_one(monkeypatch):
    fake = Report(binary="b", checks=[78], max_states=1000, error="angr failed to load")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "78"])
    assert rc == 1


# --- --fail-on CI/CD build gate -------------------------------------------


def test_fail_on_default_is_never():
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.fail_on == "never"


def test_help_lists_fail_on(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--fail-on" in out


def test_fail_on_rejects_unknown_level():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--binary", "x", "--fail-on", "critical"])


def _report_with(*confidences):
    rpt = Report(binary="b", checks=[119], max_states=1000)
    rpt.findings = [
        Finding(cwe=119, function="f", address=0x401000 + i,
                evidence="e", confidence=c)
        for i, c in enumerate(confidences)
    ]
    return rpt


def test_fail_on_never_keeps_zero_even_with_findings(monkeypatch, capsys):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("high", "medium"))
    rc = cli.main(["--binary", "b"])
    assert rc == 0
    # stdout stays clean JSON; nothing about the gate on stderr.
    json.loads(capsys.readouterr().out)


def test_fail_on_any_trips_on_any_finding(monkeypatch, capsys):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("low"))
    rc = cli.main(["--binary", "b", "--fail-on", "any"])
    assert rc == 3
    assert "fail-on" in capsys.readouterr().err


def test_fail_on_any_zero_when_no_findings(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: Report(binary="b", checks=[119], max_states=1000))
    rc = cli.main(["--binary", "b", "--fail-on", "any"])
    assert rc == 0


def test_fail_on_low_alias_of_any(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("low"))
    rc = cli.main(["--binary", "b", "--fail-on", "low"])
    assert rc == 3


def test_fail_on_high_ignores_lower_confidence(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("low", "medium"))
    rc = cli.main(["--binary", "b", "--fail-on", "high"])
    assert rc == 0


def test_fail_on_high_trips_on_high(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("medium", "high"))
    rc = cli.main(["--binary", "b", "--fail-on", "high"])
    assert rc == 3


def test_fail_on_medium_trips_on_medium_and_high(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("medium"))
    rc = cli.main(["--binary", "b", "--fail-on", "medium"])
    assert rc == 3


def test_fail_on_medium_ignores_low(monkeypatch):
    monkeypatch.setattr("autopsy.analyzer.analyze",
                        lambda **kw: _report_with("low"))
    rc = cli.main(["--binary", "b", "--fail-on", "medium"])
    assert rc == 0


def test_state_limit_takes_precedence_over_fail_on(monkeypatch, capsys):
    fake = Report(binary="b", checks=[119], max_states=10,
                  state_limit_exceeded=True, error="state limit exceeded (>10 states)")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--fail-on", "any"])
    # A genuine analysis failure (2) must not be masked by the findings gate.
    assert rc == 2


def test_engine_error_takes_precedence_over_fail_on(monkeypatch):
    fake = Report(binary="b", checks=[78], max_states=1000, error="angr failed to load")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--fail-on", "any"])
    assert rc == 1


def test_gate_treats_unknown_confidence_as_medium(monkeypatch):
    # A finding object whose confidence attribute is unexpected/unset should be
    # treated as the schema default ("medium") so the gate never silently drops
    # it under a medium threshold.
    class _F:
        confidence = "unexpected"

    assert cli._gate_tripped([_F()], "medium") is True
    assert cli._gate_tripped([_F()], "high") is False
