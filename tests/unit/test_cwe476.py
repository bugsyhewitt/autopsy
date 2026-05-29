"""Fast unit tests for the CWE-476 NULL-pointer-dereference detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned unchecked-dereference sites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe476


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(sites):
    class _E:
        def __init__(self):
            self._sites = sites

        def unchecked_alloc_dereferences(self):
            return list(self._sites)

    return _E()


def _site(address=0x401234, function="main", alloc_name="malloc",
          alloc_address=0x401200, slot="rbp-8"):
    return {
        "address": address,
        "function": function,
        "alloc_name": alloc_name,
        "alloc_address": alloc_address,
        "slot": slot,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sites():
    assert cwe476.run(_make_engine([])) == []


def test_unchecked_deref_flagged():
    engine = _make_engine([_site(address=0x401234, function="alloc_use")])
    findings = cwe476.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 476
    assert f.function == "alloc_use"
    assert f.address == 0x401234
    assert "malloc" in f.evidence
    assert "NULL" in f.evidence
    # Unchecked deref of an allocator result -> medium confidence.
    assert f.confidence == "medium"


def test_taint_trace_links_alloc_and_deref():
    engine = _make_engine([_site(address=0x401300, alloc_address=0x401200)])
    trace = cwe476.run(engine)[0].taint_trace
    assert len(trace) == 2
    assert trace[0].address == 0x401200
    assert "malloc" in trace[0].description
    assert trace[1].address == 0x401300
    assert "NULL-check" in trace[1].description


def test_multiple_sites_each_flagged():
    engine = _make_engine([
        _site(address=0x401200, function="f1"),
        _site(address=0x401280, function="f2", alloc_name="calloc"),
    ])
    findings = cwe476.run(engine)
    assert len(findings) == 2
    assert {f.address for f in findings} == {0x401200, 0x401280}
    assert all(f.confidence == "medium" for f in findings)


def test_each_allocator_named_in_evidence():
    for alloc in ("malloc", "calloc", "realloc", "strdup", "getenv"):
        engine = _make_engine([_site(alloc_name=alloc)])
        f = cwe476.run(engine)[0]
        assert alloc in f.evidence, f"{alloc} should appear in the evidence"


def test_finding_serializes_correctly():
    engine = _make_engine([_site(address=0x401234, function="compute")])
    d = cwe476.run(engine)[0].to_dict()
    assert d["cwe"] == 476
    assert d["function"] == "compute"
    assert d["address"] == "0x401234"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_cwe476_registered_in_checks():
    from autopsy.checks import CHECKS

    assert 476 in CHECKS
    assert CHECKS[476] is cwe476.run


def test_cwe476_in_scope_supported():
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 476 in SUPPORTED_CWES
    assert "476" in VALID_TOKENS


def test_cwe476_in_catalog():
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 476 in CWE_CATALOG
    assert CWE_CATALOG[476]["short"] == "NULL Pointer Dereference"
    cat = {c["cwe"] for c in list_checks()}
    assert 476 in cat


def test_cwe476_is_register_level_not_arch_agnostic():
    """CWE-476 inspects x86_64 result/slot registers, so it is NOT arch-agnostic."""
    from autopsy.engine import AngrEngine

    assert 476 not in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_476():
    from autopsy.scope import resolve_checks

    assert resolve_checks("476") == [476]
