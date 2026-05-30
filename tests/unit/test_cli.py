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
    # --binary is no longer argparse-required (so --list-checks can run without
    # a target); it is enforced in main(), which exits non-zero via
    # parser.error -> SystemExit when an analysis run omits it.
    with pytest.raises(SystemExit):
        cli.main(["--checks", "119"])


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


# --- --baseline / --write-baseline finding suppression --------------------


def _two_finding_report():
    rpt = Report(binary="b", checks=[119, 787], max_states=1000)
    rpt.findings = [
        Finding(cwe=119, function="store_at", address=0x401000,
                evidence="oob write", confidence="high"),
        Finding(cwe=787, function="copy", address=0x401200,
                evidence="heap overflow", confidence="high"),
    ]
    return rpt


def test_help_lists_baseline_flags(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--baseline" in out
    assert "--write-baseline" in out


def test_baseline_defaults_none():
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.baseline is None
    assert args.write_baseline is None


def test_write_baseline_to_stdout_then_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--write-baseline", "-"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "1"
    assert len(doc["findings"]) == 2


def test_write_baseline_to_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    path = tmp_path / "baseline.json"
    rc = cli.main(["--binary", "b", "--write-baseline", str(path)])
    assert rc == 0
    doc = json.loads(path.read_text())
    assert len(doc["findings"]) == 2
    assert "wrote baseline" in capsys.readouterr().err


def test_write_baseline_does_not_apply_fail_on(monkeypatch, tmp_path):
    # Writing a baseline must never break the build even with --fail-on set.
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    path = tmp_path / "baseline.json"
    rc = cli.main(["--binary", "b", "--write-baseline", str(path), "--fail-on", "high"])
    assert rc == 0


def test_baseline_suppresses_matching_findings(monkeypatch, tmp_path, capsys):
    from autopsy.baseline import baseline_json

    # Baseline accepts only the CWE-119 finding.
    accepted = baseline_json([
        Finding(cwe=119, function="store_at", address=0x0, evidence="oob write"),
    ])
    path = tmp_path / "baseline.json"
    path.write_text(accepted)

    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", str(path)])
    assert rc == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    # Only the CWE-787 finding survives.
    assert parsed["finding_count"] == 1
    assert parsed["findings"][0]["cwe"] == 787
    assert "suppressed 1 finding" in captured.err


def test_baseline_plus_fail_on_only_breaks_on_new_findings(monkeypatch, tmp_path):
    from autopsy.baseline import baseline_json

    # Accept BOTH findings -> nothing new -> --fail-on must not trip.
    accepted = baseline_json([
        Finding(cwe=119, function="store_at", address=0x0, evidence="oob write"),
        Finding(cwe=787, function="copy", address=0x0, evidence="heap overflow"),
    ])
    path = tmp_path / "baseline.json"
    path.write_text(accepted)

    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", str(path), "--fail-on", "high"])
    assert rc == 0


def test_baseline_fail_on_trips_on_unsuppressed_finding(monkeypatch, tmp_path):
    from autopsy.baseline import baseline_json

    # Accept only CWE-119; CWE-787 remains -> --fail-on high trips (exit 3).
    accepted = baseline_json([
        Finding(cwe=119, function="store_at", address=0x0, evidence="oob write"),
    ])
    path = tmp_path / "baseline.json"
    path.write_text(accepted)

    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", str(path), "--fail-on", "high"])
    assert rc == 3


def test_baseline_missing_file_returns_one(monkeypatch, capsys):
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", "/no/such/baseline.json"])
    assert rc == 1
    assert "cannot read baseline" in capsys.readouterr().err


def test_baseline_invalid_json_returns_one(monkeypatch, tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("not json {{{")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", str(path)])
    assert rc == 1
    assert "baseline" in capsys.readouterr().err


def test_baseline_not_applied_on_engine_error(monkeypatch, tmp_path):
    # A genuine analysis failure must take precedence; baseline is skipped and
    # the engine-error exit code (1) is returned regardless of baseline content.
    fake = Report(binary="b", checks=[78], max_states=1000, error="angr failed to load")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    path = tmp_path / "baseline.json"
    path.write_text('{"version":"1","findings":[]}')
    rc = cli.main(["--binary", "b", "--baseline", str(path)])
    assert rc == 1


# --- --list-checks offline detector catalog -------------------------------


def test_list_checks_flag_defaults_false():
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.list_checks is False


def test_help_lists_list_checks(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--list-checks" in out


def test_list_checks_text_runs_without_binary(monkeypatch, capsys):
    # Must never touch the analyzer: spy that fails if analyze() is called.
    def _boom(**kw):  # pragma: no cover - asserts it is never reached
        raise AssertionError("analyze() must not run for --list-checks")

    monkeypatch.setattr("autopsy.analyzer.analyze", _boom)
    rc = cli.main(["--list-checks"])
    assert rc == 0
    out = capsys.readouterr().out
    # Every supported CWE id and its --checks token appears in the text output.
    for cwe in (78, 119, 125, 190, 338, 367, 369, 377, 415, 416, 476, 134, 676, 732, 787):
        assert f"CWE-{cwe}" in out
        assert f"--checks {cwe}" in out
    assert "Buffer Overflow" in out


def test_list_checks_json_is_machine_readable(capsys):
    rc = cli.main(["--list-checks", "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    checks = doc["checks"]
    cwes = {c["cwe"] for c in checks}
    assert cwes == {78, 119, 125, 190, 338, 367, 369, 377, 415, 416, 476, 134, 676, 732, 787}
    sample = next(c for c in checks if c["cwe"] == 119)
    assert sample["token"] == "119"
    assert sample["short"] == "Buffer Overflow"
    assert sample["uri"].endswith("/119.html")
    assert "name" in sample


def test_list_checks_ignores_missing_binary(monkeypatch, capsys):
    # Even without --binary, --list-checks exits 0 (no parser.error).
    rc = cli.main(["--list-checks"])
    assert rc == 0
    assert capsys.readouterr().out.strip()


def test_baseline_sarif_output_excludes_suppressed(monkeypatch, tmp_path, capsys):
    from autopsy.baseline import baseline_json

    accepted = baseline_json([
        Finding(cwe=119, function="store_at", address=0x0, evidence="oob write"),
    ])
    path = tmp_path / "baseline.json"
    path.write_text(accepted)

    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: _two_finding_report())
    rc = cli.main(["--binary", "b", "--baseline", str(path), "--format", "sarif"])
    assert rc == 0
    sarif = json.loads(capsys.readouterr().out)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CWE-787"
