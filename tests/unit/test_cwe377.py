"""Fast unit tests for the CWE-377 insecure-temp-file detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned CallSites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe377
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


def _make_engine(call_sites):
    """Mock engine: call_sites_to returns only the calls whose target is queried."""

    class _E:
        def __init__(self):
            self._calls = call_sites

        def call_sites_to(self, names):
            return [cs for cs in self._calls if cs.target_name in names]

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_insecure_calls():
    """A program using only the atomic replacement → no findings."""
    engine = _make_engine([_make_cs("mkstemp"), _make_cs("mkostemp"), _make_cs("tmpfile")])
    assert cwe377.run(engine) == []


def test_tmpnam_flagged_medium_confidence():
    """tmpnam() returns a race-prone name → flagged at medium confidence."""
    engine = _make_engine([_make_cs("tmpnam", call_address=0x401130)])
    findings = cwe377.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 377
    assert f.function == "main"
    assert f.address == 0x401130
    assert "tmpnam" in f.evidence
    assert f.confidence == "medium"


def test_mktemp_flagged_medium_confidence():
    """mktemp() expands a template to a name without creating it → medium."""
    f = cwe377.run(_make_engine([_make_cs("mktemp")]))[0]
    assert f.cwe == 377
    assert f.confidence == "medium"
    assert "mktemp" in f.evidence


def test_tempnam_flagged():
    """tempnam() shares tmpnam's TOCTOU race → flagged."""
    f = cwe377.run(_make_engine([_make_cs("tempnam")]))[0]
    assert f.cwe == 377
    assert f.confidence == "medium"
    assert "tempnam" in f.evidence


def test_tmpnam_r_alias_flagged():
    """tmpnam_r() (the reentrant variant) is equally race-prone → flagged."""
    f = cwe377.run(_make_engine([_make_cs("tmpnam_r")]))[0]
    assert f.cwe == 377
    assert "tmpnam_r" in f.evidence


def test_atomic_replacements_never_flagged():
    """The atomic create-and-open functions must NOT fire (zero false positives)."""
    safe = ["mkstemp", "mkostemp", "tmpfile", "open", "fopen"]
    engine = _make_engine([_make_cs(name) for name in safe])
    assert cwe377.run(engine) == []


def test_multiple_insecure_calls_each_flagged():
    """tmpnam + mktemp + tempnam → three distinct findings."""
    engine = _make_engine(
        [
            _make_cs("tmpnam", caller_function="main", call_address=0x401130),
            _make_cs("mktemp", caller_function="main", call_address=0x401150),
            _make_cs("tempnam", caller_function="main", call_address=0x401180),
        ]
    )
    findings = cwe377.run(engine)
    assert len(findings) == 3
    addrs = {f.address for f in findings}
    assert addrs == {0x401130, 0x401150, 0x401180}
    assert all(f.confidence == "medium" for f in findings)


def test_evidence_names_replacement():
    """Evidence steers the user to the atomic mkstemp replacement."""
    f = cwe377.run(_make_engine([_make_cs("tmpnam")]))[0]
    assert "mkstemp" in f.evidence


def test_finding_has_one_taint_trace_point():
    """The 'taint trace' for an insecure-temp-file use is the call site itself."""
    trace = cwe377.run(_make_engine([_make_cs("tmpnam")]))[0].taint_trace
    assert len(trace) == 1
    assert "tmpnam" in trace[0].description


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    d = cwe377.run(_make_engine([_make_cs("tmpnam", call_address=0x401130)]))[0].to_dict()
    assert d["cwe"] == 377
    assert d["function"] == "main"
    assert d["address"] == "0x401130"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 1
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_cwe377_registered_in_checks():
    """CWE-377 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 377 in CHECKS
    assert CHECKS[377] is cwe377.run


def test_cwe377_in_scope_supported():
    """CWE-377 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 377 in SUPPORTED_CWES
    assert "377" in VALID_TOKENS


def test_cwe377_in_catalog():
    """CWE-377 must carry catalog metadata so --list-checks and SARIF name it."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 377 in CWE_CATALOG
    assert CWE_CATALOG[377]["short"] == "Insecure Temp File"
    cat = {c["cwe"] for c in list_checks()}
    assert 377 in cat


def test_cwe377_is_arch_agnostic():
    """CWE-377 is call-site-driven, so it must run on AArch64 (not skipped)."""
    from autopsy.engine import AngrEngine

    assert 377 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_377():
    """resolve_checks('377') resolves to exactly [377]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("377") == [377]
