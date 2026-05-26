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
    # The choices for --checks must include all five tokens.
    for tok in ("119", "190", "416", "78", "all"):
        assert tok in out


def test_checks_default_is_all():
    args = cli.build_parser().parse_args(["--binary", "x"])
    assert args.checks == "all"
    assert args.max_states == 1000
    assert args.format == "json"


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


def test_main_engine_error_returns_one(monkeypatch):
    fake = Report(binary="b", checks=[78], max_states=1000, error="angr failed to load")
    monkeypatch.setattr("autopsy.analyzer.analyze", lambda **kw: fake)
    rc = cli.main(["--binary", "b", "--checks", "78"])
    assert rc == 1
