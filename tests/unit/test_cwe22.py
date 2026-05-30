"""Fast unit tests for the CWE-22 path-traversal detector. angr-free.

These tests verify the check's detection logic using a mock engine that
returns pre-canned CallSite lists for source/sink/sanitizer queries, with no
angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe22
from autopsy.engine import CallSite


def _make_cs(target_name, caller_function="main", call_address=0x400500, block_addr=0x400500):
    return CallSite(
        caller_function=caller_function,
        call_address=call_address,
        target_name=target_name,
        block_addr=block_addr,
    )


def _make_engine(sinks=(), sources=(), sanitizers=()):
    """Mock engine: dispatch call_sites_to by the name set passed in.

    The CWE-22 check queries the engine three times, once per (sinks, sources,
    sanitizers) name set. We dispatch by membership in the canonical sets the
    check defines so the mock matches the check's call shape exactly.
    """

    class _E:
        def call_sites_to(self, names):
            # The check's three queries are distinguishable by which canonical
            # set the names argument matches.
            if "fopen" in names or "open" in names or "unlink" in names:
                return list(sinks)
            if "fgets" in names or "read" in names or "getenv" in names:
                return list(sources)
            if "realpath" in names:
                return list(sanitizers)
            return []

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sinks():
    """No path-sink calls -> no findings."""
    engine = _make_engine(sinks=[], sources=[_make_cs("fgets")])
    assert cwe22.run(engine) == []


def test_no_findings_when_no_input_source():
    """A path sink but no attacker input source -> no finding."""
    engine = _make_engine(sinks=[_make_cs("fopen", call_address=0x4011aa)], sources=[])
    assert cwe22.run(engine) == []


def test_no_findings_when_sanitizer_present():
    """If the program calls realpath() anywhere, suppress to preserve zero-FP."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
        sanitizers=[_make_cs("realpath")],
    )
    assert cwe22.run(engine) == []


def test_finding_emitted_for_fopen_with_source():
    """fopen + an input source + no sanitizer -> one CWE-22 finding."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", caller_function="serve_file", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    findings = cwe22.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 22
    assert f.function == "serve_file"
    assert f.address == 0x4011aa
    assert "fopen" in f.evidence


def test_finding_for_unlink_has_medium_confidence():
    """unlink() is state-changing -> medium confidence."""
    engine = _make_engine(
        sinks=[_make_cs("unlink", call_address=0x401200)],
        sources=[_make_cs("recv")],
    )
    findings = cwe22.run(engine)
    assert findings[0].confidence == "medium"


def test_finding_for_stat_has_low_confidence():
    """stat() is read-only metadata -> low confidence (still a finding)."""
    engine = _make_engine(
        sinks=[_make_cs("stat", call_address=0x401300)],
        sources=[_make_cs("fgets")],
    )
    findings = cwe22.run(engine)
    assert findings[0].confidence == "low"


def test_finding_has_two_taint_trace_points():
    """Taint trace: source point + sink point."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    trace = cwe22.run(engine)[0].taint_trace
    assert len(trace) == 2


def test_taint_trace_mentions_source_and_sink():
    """Trace point 0 names the source; point 1 names the sink."""
    engine = _make_engine(
        sinks=[_make_cs("openat", call_address=0x4011aa)],
        sources=[_make_cs("read")],
    )
    trace = cwe22.run(engine)[0].taint_trace
    assert "read" in trace[0].description
    assert "openat" in trace[1].description


def test_earliest_source_used_as_taint_origin():
    """When multiple sources exist, the earliest call address is the origin."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", call_address=0x4011aa)],
        sources=[
            _make_cs("read", call_address=0x400900),
            _make_cs("fgets", call_address=0x400500),
        ],
    )
    trace = cwe22.run(engine)[0].taint_trace
    assert trace[0].address == 0x400500
    assert "fgets" in trace[0].description


def test_multiple_sinks_each_flagged():
    """Two sink calls -> two findings."""
    engine = _make_engine(
        sinks=[
            _make_cs("fopen", caller_function="serve", call_address=0x4011aa),
            _make_cs("unlink", caller_function="purge", call_address=0x4012aa),
        ],
        sources=[_make_cs("fgets")],
    )
    findings = cwe22.run(engine)
    assert len(findings) == 2
    funcs = {f.function for f in findings}
    assert funcs == {"serve", "purge"}


def test_getenv_counts_as_attacker_source():
    """getenv() reads attacker-influenced environment -> qualifies as source."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", call_address=0x4011aa)],
        sources=[_make_cs("getenv", call_address=0x400600)],
    )
    findings = cwe22.run(engine)
    assert len(findings) == 1
    assert "getenv" in findings[0].taint_trace[0].description


def test_finding_serializes_correctly():
    """to_dict() produces the v0.1 contract fields including confidence."""
    engine = _make_engine(
        sinks=[_make_cs("fopen", caller_function="serve_file", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    d = cwe22.run(engine)[0].to_dict()
    assert d["cwe"] == 22
    assert d["function"] == "serve_file"
    assert d["address"] == "0x4011aa"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] in ("low", "medium")


def test_cwe22_registered_in_checks():
    """CWE-22 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS
    assert 22 in CHECKS
    assert CHECKS[22] is cwe22.run


def test_cwe22_in_scope_supported():
    """CWE-22 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS, CWE_CATALOG, resolve_checks
    assert 22 in SUPPORTED_CWES
    assert "22" in VALID_TOKENS
    assert 22 in CWE_CATALOG
    assert resolve_checks("22") == [22]
