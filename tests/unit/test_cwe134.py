"""Fast unit tests for the CWE-134 uncontrolled-format-string detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned non-literal-format sinks and CallSite sources, with no angr
dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe134
from autopsy.engine import CallSite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cs(target_name, caller_function="main", call_address=0x400500, block_addr=0x400500):
    return CallSite(
        caller_function=caller_function,
        call_address=call_address,
        target_name=target_name,
        block_addr=block_addr,
    )


def _sink(function="emit", call_address=0x401188, sink_name="printf",
          fmt_reg="rdi", fmt_slot="rbp-0x8"):
    return {
        "function": function,
        "call_address": call_address,
        "sink_name": sink_name,
        "fmt_reg": fmt_reg,
        "fmt_slot": fmt_slot,
    }


def _make_engine(sinks, sources):
    """Mock engine: format_string_sinks_* returns sinks, call_sites_to sources."""

    class _E:
        def __init__(self):
            self._sinks = sinks
            self._sources = sources

        def format_string_sinks_with_nonliteral_format(self):
            return self._sinks

        def call_sites_to(self, names):
            # Any query in this check is the _SOURCES set.
            return self._sources

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_nonliteral_sinks():
    """No non-literal format sinks → no findings (all formats are literals)."""
    engine = _make_engine(sinks=[], sources=[_make_cs("fgets")])
    assert cwe134.run(engine) == []


def test_no_findings_when_no_input_source():
    """A non-literal format but no attacker input source → no finding."""
    engine = _make_engine(sinks=[_sink()], sources=[])
    assert cwe134.run(engine) == []


def test_finding_emitted_for_nonliteral_printf_with_source():
    """Non-literal printf + an input source → one CWE-134 finding."""
    engine = _make_engine(sinks=[_sink()], sources=[_make_cs("fgets")])
    findings = cwe134.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 134
    assert f.function == "emit"
    assert f.address == 0x401188
    assert "printf" in f.evidence
    assert "format" in f.evidence.lower()


def test_finding_has_medium_confidence():
    """CWE-134 findings carry confidence='medium'."""
    engine = _make_engine(sinks=[_sink()], sources=[_make_cs("read")])
    assert cwe134.run(engine)[0].confidence == "medium"


def test_finding_has_two_taint_trace_points():
    """Taint trace: source point + sink point."""
    engine = _make_engine(sinks=[_sink()], sources=[_make_cs("fgets")])
    trace = cwe134.run(engine)[0].taint_trace
    assert len(trace) == 2


def test_taint_trace_mentions_source_and_sink():
    """Trace point 0 names the input source; point 1 names the format sink."""
    engine = _make_engine(
        sinks=[_sink(sink_name="snprintf")],
        sources=[_make_cs("fgets")],
    )
    trace = cwe134.run(engine)[0].taint_trace
    assert "fgets" in trace[0].description
    assert "snprintf" in trace[1].description


def test_earliest_source_used_as_taint_origin():
    """When multiple sources exist, the earliest call address is the origin."""
    engine = _make_engine(
        sinks=[_sink()],
        sources=[
            _make_cs("read", call_address=0x400900),
            _make_cs("fgets", call_address=0x400500),
        ],
    )
    trace = cwe134.run(engine)[0].taint_trace
    assert trace[0].address == 0x400500
    assert "fgets" in trace[0].description


def test_multiple_nonliteral_sinks_each_flagged():
    """Two non-literal sinks → two findings."""
    engine = _make_engine(
        sinks=[
            _sink(function="emit", call_address=0x401188, sink_name="printf"),
            _sink(function="log", call_address=0x4012aa, sink_name="syslog",
                  fmt_reg="rsi", fmt_slot="rbp-0x10"),
        ],
        sources=[_make_cs("fgets")],
    )
    findings = cwe134.run(engine)
    assert len(findings) == 2
    funcs = {f.function for f in findings}
    assert funcs == {"emit", "log"}


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    engine = _make_engine(sinks=[_sink()], sources=[_make_cs("fgets")])
    d = cwe134.run(engine)[0].to_dict()
    assert d["cwe"] == 134
    assert d["function"] == "emit"
    assert d["address"] == "0x401188"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_engine_without_helper_returns_empty():
    """An engine lacking the format-sink helper (e.g. older mock) → no findings."""

    class _Bare:
        def call_sites_to(self, names):
            return [_make_cs("fgets")]

    assert cwe134.run(_Bare()) == []


def test_cwe134_registered_in_checks():
    """CWE-134 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS
    assert 134 in CHECKS
    assert CHECKS[134] is cwe134.run


def test_cwe134_in_scope_supported():
    """CWE-134 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS
    assert 134 in SUPPORTED_CWES
    assert "134" in VALID_TOKENS
