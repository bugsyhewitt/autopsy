"""Fast unit tests for the CWE-369 divide-by-zero detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned division sites and CallSites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe369
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


def _make_engine(divisions, call_sites):
    """Mock engine.

    ``divisions_with_unguarded_divisor`` returns the canned division dicts.
    ``call_sites_to`` returns only the calls whose target is queried.
    """

    class _E:
        def __init__(self):
            self._divs = divisions
            self._calls = call_sites

        def divisions_with_unguarded_divisor(self):
            return list(self._divs)

        def call_sites_to(self, names):
            return [cs for cs in self._calls if cs.target_name in names]

    return _E()


def _div(address=0x401200, function="main", divisor="ecx"):
    return {"address": address, "function": function, "divisor": divisor}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_divisions():
    """No division instructions -> no findings, regardless of input sources."""
    engine = _make_engine([], [_make_cs("atoi")])
    assert cwe369.run(engine) == []


def test_no_findings_when_no_input_source():
    """An unguarded division but no attacker input -> no finding (not CWE-369)."""
    engine = _make_engine([_div()], [])
    assert cwe369.run(engine) == []


def test_unguarded_division_with_source_flagged():
    """Unguarded divisor + an input source present -> a medium-confidence finding."""
    engine = _make_engine(
        [_div(address=0x401234, function="compute", divisor="ecx")],
        [_make_cs("atoi", call_address=0x401100)],
    )
    findings = cwe369.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 369
    assert f.function == "compute"
    assert f.address == 0x401234
    assert "ecx" in f.evidence
    assert "atoi" in f.evidence
    assert f.confidence == "medium"


def test_finding_taint_trace_links_source_and_division():
    """The taint trace runs from the input source to the division site."""
    engine = _make_engine(
        [_div(address=0x401300)],
        [_make_cs("scanf", call_address=0x401080)],
    )
    trace = cwe369.run(engine)[0].taint_trace
    assert len(trace) == 2
    assert trace[0].address == 0x401080
    assert "scanf" in trace[0].description
    assert trace[1].address == 0x401300
    assert "unguarded" in trace[1].description


def test_multiple_divisions_each_flagged():
    """Two unguarded divisions -> two distinct findings."""
    engine = _make_engine(
        [
            _div(address=0x401200, function="f1", divisor="ecx"),
            _div(address=0x401280, function="f2", divisor="rbx"),
        ],
        [_make_cs("read")],
    )
    findings = cwe369.run(engine)
    assert len(findings) == 2
    assert {f.address for f in findings} == {0x401200, 0x401280}
    assert all(f.confidence == "medium" for f in findings)


def test_memory_divisor_reported_verbatim():
    """A memory-operand divisor is reported in the evidence verbatim."""
    engine = _make_engine(
        [_div(divisor="dword ptr [rbp - 4]")],
        [_make_cs("strtol")],
    )
    f = cwe369.run(engine)[0]
    assert "dword ptr [rbp - 4]" in f.evidence


def test_each_source_kind_enables_detection():
    """Any of the recognized input sources enables a finding."""
    for src in ("fgets", "gets", "read", "scanf", "atoi", "strtol"):
        engine = _make_engine([_div()], [_make_cs(src)])
        findings = cwe369.run(engine)
        assert len(findings) == 1, f"source {src} should enable a finding"
        assert src in findings[0].evidence


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    engine = _make_engine(
        [_div(address=0x401234, function="compute")],
        [_make_cs("atoi")],
    )
    d = cwe369.run(engine)[0].to_dict()
    assert d["cwe"] == 369
    assert d["function"] == "compute"
    assert d["address"] == "0x401234"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_cwe369_registered_in_checks():
    """CWE-369 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 369 in CHECKS
    assert CHECKS[369] is cwe369.run


def test_cwe369_in_scope_supported():
    """CWE-369 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 369 in SUPPORTED_CWES
    assert "369" in VALID_TOKENS


def test_cwe369_in_catalog():
    """CWE-369 must carry catalog metadata so --list-checks and SARIF name it."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 369 in CWE_CATALOG
    assert CWE_CATALOG[369]["short"] == "Divide By Zero"
    cat = {c["cwe"] for c in list_checks()}
    assert 369 in cat


def test_cwe369_is_arch_aware_runs_on_aarch64():
    """CWE-369's divisor/guard reasoning is arch-aware (x86_64 div/idiv and
    AArch64 sdiv/udiv), so it is in the arch-agnostic set and runs on AArch64."""
    from autopsy.engine import AngrEngine

    assert 369 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_369():
    """resolve_checks('369') resolves to exactly [369]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("369") == [369]
