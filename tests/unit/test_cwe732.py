"""Fast unit tests for the CWE-732 incorrect-permission-assignment detector.

angr-free. A mock engine returns pre-canned chmod/umask site dicts (the shape
the real engine helpers produce), so the check's finding-construction logic is
exercised without importing angr.
"""

from __future__ import annotations

from autopsy.checks import cwe732


def _make_engine(chmod_sites=None, umask_sites=None):
    """Mock engine exposing the two CWE-732 helpers."""

    class _E:
        def chmod_calls_with_permissive_mode(self):
            return chmod_sites or []

        def umask_calls_with_permissive_mask(self):
            return umask_sites or []

    return _E()


def _chmod_site(mode, function="setup", address=0x401130, sink_name="chmod"):
    return {"address": address, "function": function, "sink_name": sink_name, "mode": mode}


def _umask_site(mode, function="init", address=0x401200):
    return {"address": address, "function": function, "sink_name": "umask", "mode": mode}


# ---------------------------------------------------------------------------
# chmod-family findings
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sites():
    assert cwe732.run(_make_engine()) == []


def test_chmod_world_writable_flagged_high():
    f = cwe732.run(_make_engine(chmod_sites=[_chmod_site(0o777, address=0x401130)]))[0]
    assert f.cwe == 732
    assert f.function == "setup"
    assert f.address == 0x401130
    assert f.confidence == "high"
    assert "0o777" in f.evidence
    assert "chmod" in f.evidence
    assert "world-write" in f.evidence


def test_chmod_group_world_write_flagged():
    f = cwe732.run(_make_engine(chmod_sites=[_chmod_site(0o666)]))[0]
    assert f.cwe == 732
    assert "0o666" in f.evidence
    assert "group-write" in f.evidence and "world-write" in f.evidence


def test_chmod_group_only_write_flagged():
    # 0o620: group-write set, world bits clear -> still beyond owner.
    f = cwe732.run(_make_engine(chmod_sites=[_chmod_site(0o620)]))[0]
    assert f.cwe == 732
    assert "group-write" in f.evidence
    assert "world-write" not in f.evidence


def test_fchmodat_sink_name_in_evidence():
    f = cwe732.run(
        _make_engine(chmod_sites=[_chmod_site(0o777, sink_name="fchmodat")])
    )[0]
    assert "fchmodat" in f.evidence


def test_multiple_chmod_sites_each_flagged():
    findings = cwe732.run(
        _make_engine(
            chmod_sites=[
                _chmod_site(0o777, function="a", address=0x401100),
                _chmod_site(0o666, function="b", address=0x401200),
            ]
        )
    )
    assert len(findings) == 2
    assert {f.address for f in findings} == {0x401100, 0x401200}
    assert all(f.confidence == "high" for f in findings)


# ---------------------------------------------------------------------------
# umask findings
# ---------------------------------------------------------------------------


def test_umask_zero_flagged_medium():
    f = cwe732.run(_make_engine(umask_sites=[_umask_site(0, address=0x401200)]))[0]
    assert f.cwe == 732
    assert f.function == "init"
    assert f.address == 0x401200
    assert f.confidence == "medium"
    assert "umask(0o0)" in f.evidence or "umask(0o" in f.evidence
    assert "group/other write" in f.evidence


def test_umask_partial_mask_flagged():
    # 0o002 strips only world-write; group-write (0o020) left unmasked.
    f = cwe732.run(_make_engine(umask_sites=[_umask_site(0o002)]))[0]
    assert f.cwe == 732
    assert f.confidence == "medium"


def test_chmod_and_umask_both_reported():
    findings = cwe732.run(
        _make_engine(
            chmod_sites=[_chmod_site(0o777, address=0x401100)],
            umask_sites=[_umask_site(0, address=0x401200)],
        )
    )
    assert len(findings) == 2
    cwes = {f.cwe for f in findings}
    assert cwes == {732}
    confidences = {f.confidence for f in findings}
    assert confidences == {"high", "medium"}


def test_finding_has_one_taint_trace_point():
    f = cwe732.run(_make_engine(chmod_sites=[_chmod_site(0o777)]))[0]
    assert len(f.taint_trace) == 1
    assert "chmod" in f.taint_trace[0].description


def test_finding_serializes_correctly():
    d = cwe732.run(
        _make_engine(chmod_sites=[_chmod_site(0o777, address=0x401130)])
    )[0].to_dict()
    assert d["cwe"] == 732
    assert d["function"] == "setup"
    assert d["address"] == "0x401130"
    assert isinstance(d["taint_trace"], list) and len(d["taint_trace"]) == 1
    assert d["evidence"]
    assert d["confidence"] == "high"


# ---------------------------------------------------------------------------
# Registration / scope wiring
# ---------------------------------------------------------------------------


def test_cwe732_registered_in_checks():
    from autopsy.checks import CHECKS

    assert 732 in CHECKS
    assert CHECKS[732] is cwe732.run


def test_cwe732_in_scope_supported():
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 732 in SUPPORTED_CWES
    assert "732" in VALID_TOKENS


def test_cwe732_in_catalog():
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 732 in CWE_CATALOG
    assert CWE_CATALOG[732]["short"] == "Incorrect Permission Assignment"
    assert 732 in {c["cwe"] for c in list_checks()}


def test_cwe732_is_register_level_not_arch_agnostic():
    """CWE-732 reads x86_64 mode registers, so it is NOT arch-agnostic."""
    from autopsy.engine import AngrEngine

    assert 732 not in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_732():
    from autopsy.scope import resolve_checks

    assert resolve_checks("732") == [732]
