"""Fast unit tests for the analysis driver with a MOCKED angr boundary.

These verify scope dispatch, finding aggregation, and state-limit/error
handling without importing angr. A fake engine factory is injected; the real
check functions are monkeypatched so we exercise the driver, not detection.
"""

import pytest

from autopsy import analyzer
from autopsy.report import Finding


class FakeEngine:
    """Stand-in for AngrEngine; carries no angr dependency."""

    def __init__(self, binary, max_states):
        self.binary = binary
        self.max_states = max_states


def _fake_factory(binary, max_states):
    return FakeEngine(binary, max_states)


def test_analyze_runs_selected_check_only(monkeypatch):
    calls = []

    def fake_119(engine):
        calls.append(119)
        return [Finding(cwe=119, function="f", address=0x1, evidence="e")]

    def fake_78(engine):
        calls.append(78)
        return []

    monkeypatch.setitem(analyzer.__dict__.setdefault("_patched", {}), "x", 1)
    monkeypatch.setattr("autopsy.checks.CHECKS", {119: fake_119, 190: fake_78,
                                                  415: fake_78, 416: fake_78, 78: fake_78})
    rep = analyzer.analyze("bin", "119", engine_factory=_fake_factory)
    assert calls == [119]
    assert rep.checks == [119]
    assert len(rep.findings) == 1
    assert rep.findings[0].cwe == 119


def test_analyze_all_runs_every_check(monkeypatch):
    seen = []
    monkeypatch.setattr(
        "autopsy.checks.CHECKS",
        {c: (lambda e, c=c: (seen.append(c) or [])) for c in (119, 190, 415, 416, 78)},
    )
    rep = analyzer.analyze("bin", "all", engine_factory=_fake_factory)
    assert seen == [119, 190, 415, 416, 78]
    assert rep.findings == []


def test_analyze_propagates_state_limit(monkeypatch):
    from autopsy.engine import StateLimitExceeded

    def boom(engine):
        raise StateLimitExceeded("state limit exceeded (>10 states)")

    monkeypatch.setattr("autopsy.checks.CHECKS", {119: boom})
    rep = analyzer.analyze("bin", "119", max_states=10, engine_factory=_fake_factory)
    assert rep.state_limit_exceeded is True
    assert "state limit exceeded" in rep.error


def test_analyze_handles_engine_load_error(monkeypatch):
    from autopsy.engine import EngineError

    def bad_factory(binary, max_states):
        raise EngineError("angr failed to load 'bin'")

    rep = analyzer.analyze("bin", "all", engine_factory=bad_factory)
    assert rep.error is not None
    assert "angr failed to load" in rep.error
    assert rep.findings == []
