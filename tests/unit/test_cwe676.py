"""Fast unit tests for the CWE-676 dangerous-function detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned CallSites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe676
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
    """Mock engine: call_sites_to returns only the dangerous calls in ``names``."""

    class _E:
        def __init__(self):
            self._calls = call_sites

        def call_sites_to(self, names):
            # Mirror the real engine: only return calls whose target is queried.
            return [cs for cs in self._calls if cs.target_name in names]

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_dangerous_calls():
    """A program calling only safe functions → no findings."""
    engine = _make_engine([_make_cs("strncpy"), _make_cs("snprintf"), _make_cs("fgets")])
    assert cwe676.run(engine) == []


def test_gets_flagged_high_confidence():
    """gets() admits no safe usage → flagged at high confidence."""
    engine = _make_engine([_make_cs("gets", call_address=0x401130)])
    findings = cwe676.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 676
    assert f.function == "main"
    assert f.address == 0x401130
    assert "gets" in f.evidence
    assert f.confidence == "high"


def test_strcpy_flagged_medium_confidence():
    """strcpy() is a strong red flag but can be used safely → medium."""
    f = cwe676.run(_make_engine([_make_cs("strcpy")]))[0]
    assert f.cwe == 676
    assert f.confidence == "medium"
    assert "strcpy" in f.evidence


def test_sprintf_flagged_medium_confidence():
    """sprintf() unbounded formatted write → medium confidence."""
    f = cwe676.run(_make_engine([_make_cs("sprintf")]))[0]
    assert f.confidence == "medium"
    assert "sprintf" in f.evidence


def test_isoc99_scanf_alias_flagged():
    """glibc emits scanf under the __isoc99_scanf alias → still flagged."""
    f = cwe676.run(_make_engine([_make_cs("__isoc99_scanf")]))[0]
    assert f.cwe == 676
    assert f.confidence == "medium"
    assert "__isoc99_scanf" in f.evidence


def test_bounded_siblings_never_flagged():
    """The bounded replacements must NOT fire (zero false positives)."""
    safe = ["strncpy", "strncat", "snprintf", "vsnprintf", "fgets", "strlcpy"]
    engine = _make_engine([_make_cs(name) for name in safe])
    assert cwe676.run(engine) == []


def test_multiple_dangerous_calls_each_flagged():
    """gets + strcpy + sprintf → three distinct findings."""
    engine = _make_engine(
        [
            _make_cs("gets", caller_function="main", call_address=0x401130),
            _make_cs("strcpy", caller_function="main", call_address=0x401150),
            _make_cs("sprintf", caller_function="main", call_address=0x401180),
        ]
    )
    findings = cwe676.run(engine)
    assert len(findings) == 3
    targets = {f.address for f in findings}
    assert targets == {0x401130, 0x401150, 0x401180}
    # gets is high, the others medium.
    by_addr = {f.address: f.confidence for f in findings}
    assert by_addr[0x401130] == "high"
    assert by_addr[0x401150] == "medium"
    assert by_addr[0x401180] == "medium"


def test_evidence_names_replacement():
    """Evidence steers the user to the bounded replacement."""
    f = cwe676.run(_make_engine([_make_cs("strcpy")]))[0]
    assert "strncpy" in f.evidence or "strlcpy" in f.evidence


def test_finding_has_one_taint_trace_point():
    """The 'taint trace' for a use-of-dangerous-function is the call site itself."""
    trace = cwe676.run(_make_engine([_make_cs("gets")]))[0].taint_trace
    assert len(trace) == 1
    assert "gets" in trace[0].description


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    d = cwe676.run(_make_engine([_make_cs("gets", call_address=0x401130)]))[0].to_dict()
    assert d["cwe"] == 676
    assert d["function"] == "main"
    assert d["address"] == "0x401130"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 1
    assert d["evidence"]
    assert d["confidence"] == "high"


def test_cwe676_registered_in_checks():
    """CWE-676 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 676 in CHECKS
    assert CHECKS[676] is cwe676.run


def test_cwe676_in_scope_supported():
    """CWE-676 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 676 in SUPPORTED_CWES
    assert "676" in VALID_TOKENS


def test_cwe676_in_catalog():
    """CWE-676 must carry catalog metadata so --list-checks and SARIF name it."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 676 in CWE_CATALOG
    assert CWE_CATALOG[676]["short"] == "Dangerous Function"
    cat = {c["cwe"] for c in list_checks()}
    assert 676 in cat


def test_cwe676_is_arch_agnostic():
    """CWE-676 is call-site-driven, so it must run on AArch64 (not skipped)."""
    from autopsy.engine import AngrEngine

    assert 676 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_676():
    """resolve_checks('676') resolves to exactly [676]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("676") == [676]
