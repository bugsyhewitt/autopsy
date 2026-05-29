"""Fast unit tests for the CWE-367 TOCTOU race-condition detector.

angr-free. A mock engine returns pre-canned check->use sequence dicts (the shape
the real ``AngrEngine.toctou_check_then_use_sequences`` helper produces), so the
check's finding-construction logic is exercised without importing angr.
"""

from __future__ import annotations

from autopsy.checks import cwe367


def _make_engine(sequences=None):
    """Mock engine exposing the single CWE-367 helper."""

    class _E:
        def toctou_check_then_use_sequences(self):
            return sequences or []

    return _E()


def _seq(
    check_name="access",
    use_name="open",
    function="handle",
    check_address=0x401100,
    use_address=0x401120,
):
    return {
        "function": function,
        "check_name": check_name,
        "check_address": check_address,
        "use_name": use_name,
        "use_address": use_address,
    }


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sequences():
    assert cwe367.run(_make_engine()) == []


def test_access_then_open_flagged_medium():
    f = cwe367.run(_make_engine([_seq()]))[0]
    assert f.cwe == 367
    assert f.function == "handle"
    # The finding is anchored at the time-of-use (where the damage lands).
    assert f.address == 0x401120
    assert f.confidence == "medium"
    assert "access" in f.evidence
    assert "open" in f.evidence
    assert "TOCTOU" in f.evidence or "race" in f.evidence


def test_finding_has_two_taint_points_check_and_use():
    f = cwe367.run(_make_engine([_seq()]))[0]
    assert len(f.taint_trace) == 2
    assert f.taint_trace[0].address == 0x401100
    assert f.taint_trace[1].address == 0x401120
    assert "time-of-check" in f.taint_trace[0].description
    assert "time-of-use" in f.taint_trace[1].description


def test_stat_then_fopen_flagged():
    f = cwe367.run(
        _make_engine([_seq(check_name="stat", use_name="fopen", function="loader")])
    )[0]
    assert f.function == "loader"
    assert "stat" in f.evidence
    assert "fopen" in f.evidence


def test_lstat_then_unlink_flagged():
    f = cwe367.run(
        _make_engine([_seq(check_name="lstat", use_name="unlink", function="cleanup")])
    )[0]
    assert f.function == "cleanup"
    assert "lstat" in f.evidence
    assert "unlink" in f.evidence


def test_known_pair_uses_specific_fix_hint():
    f = cwe367.run(_make_engine([_seq(check_name="access", use_name="open")]))[0]
    # The access->open pairing has a tailored remediation hint.
    assert "fd" in f.evidence


def test_unknown_pair_uses_generic_fix():
    f = cwe367.run(
        _make_engine([_seq(check_name="faccessat", use_name="rename")])
    )[0]
    assert "descriptor" in f.evidence or "O_NOFOLLOW" in f.evidence


def test_multiple_sequences_each_flagged():
    findings = cwe367.run(
        _make_engine(
            [
                _seq(function="a", check_address=0x401100, use_address=0x401110),
                _seq(function="b", check_address=0x401200, use_address=0x401210),
            ]
        )
    )
    assert len(findings) == 2
    assert {f.address for f in findings} == {0x401110, 0x401210}
    assert all(f.confidence == "medium" for f in findings)


def test_finding_serializes_correctly():
    d = cwe367.run(_make_engine([_seq(use_address=0x401120)]))[0].to_dict()
    assert d["cwe"] == 367
    assert d["function"] == "handle"
    assert d["address"] == "0x401120"
    assert isinstance(d["taint_trace"], list) and len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


# ---------------------------------------------------------------------------
# Registration / scope wiring
# ---------------------------------------------------------------------------


def test_cwe367_registered_in_checks():
    from autopsy.checks import CHECKS

    assert 367 in CHECKS
    assert CHECKS[367] is cwe367.run


def test_cwe367_in_scope_supported():
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 367 in SUPPORTED_CWES
    assert "367" in VALID_TOKENS


def test_cwe367_in_catalog():
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 367 in CWE_CATALOG
    assert CWE_CATALOG[367]["short"] == "TOCTOU Race Condition"
    assert 367 in {c["cwe"] for c in list_checks()}


def test_cwe367_is_arch_agnostic():
    """CWE-367 is call-site-driven, so it runs on AArch64 too."""
    from autopsy.engine import AngrEngine

    assert 367 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_367():
    from autopsy.scope import resolve_checks

    assert resolve_checks("367") == [367]
