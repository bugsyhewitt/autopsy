"""Fast unit tests for the CWE-401 memory-leak detector. angr-free.

These tests verify the check's detection logic using a mock engine that
returns pre-canned unfreed-allocation sites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe401


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(sites):
    class _E:
        def __init__(self):
            self._sites = sites

        def unfreed_allocations(self):
            return list(self._sites)

    return _E()


def _site(address=0x401234, function="leaky", alloc_name="malloc",
          alloc_address=0x401234, slot="rbp-8"):
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
    assert cwe401.run(_make_engine([])) == []


def test_unfreed_allocation_flagged():
    engine = _make_engine([_site(function="leaky", address=0x401234)])
    findings = cwe401.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 401
    assert f.function == "leaky"
    assert f.address == 0x401234
    assert "malloc" in f.evidence
    assert "leaks" in f.evidence
    # An owned allocator with no observed release or escape -> medium.
    assert f.confidence == "medium"


def test_taint_trace_links_alloc_and_anchor():
    engine = _make_engine([_site(address=0x401300, alloc_address=0x401300)])
    trace = cwe401.run(engine)[0].taint_trace
    assert len(trace) == 2
    assert trace[0].address == 0x401300
    assert "malloc" in trace[0].description
    assert "owns" in trace[0].description
    assert trace[1].address == 0x401300
    assert "never released" in trace[1].description


def test_multiple_sites_each_flagged():
    engine = _make_engine([
        _site(address=0x401200, function="f1"),
        _site(address=0x401280, function="f2", alloc_name="calloc"),
    ])
    findings = cwe401.run(engine)
    assert len(findings) == 2
    assert {f.address for f in findings} == {0x401200, 0x401280}
    assert all(f.confidence == "medium" for f in findings)


def test_each_owned_allocator_named_in_evidence():
    # CWE-401 tracks ONLY allocators whose return value the caller owns.
    # getenv/secure_getenv are deliberately excluded (caller must not free
    # environment storage), so the catalog mirrors the engine helper.
    for alloc in ("malloc", "calloc", "realloc", "reallocarray", "strdup",
                  "strndup"):
        engine = _make_engine([_site(alloc_name=alloc)])
        f = cwe401.run(engine)[0]
        assert alloc in f.evidence, f"{alloc} should appear in the evidence"


def test_finding_serializes_correctly():
    engine = _make_engine([_site(address=0x401234, function="compute")])
    d = cwe401.run(engine)[0].to_dict()
    assert d["cwe"] == 401
    assert d["function"] == "compute"
    assert d["address"] == "0x401234"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_cwe401_registered_in_checks():
    from autopsy.checks import CHECKS

    assert 401 in CHECKS
    assert CHECKS[401] is cwe401.run


def test_cwe401_in_scope_supported():
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 401 in SUPPORTED_CWES
    assert "401" in VALID_TOKENS


def test_cwe401_in_catalog():
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 401 in CWE_CATALOG
    assert CWE_CATALOG[401]["short"] == "Memory Leak"
    cat = {c["cwe"] for c in list_checks()}
    assert 401 in cat


def test_cwe401_is_arch_agnostic():
    """CWE-401 runs on both x86_64 and AArch64 (arch-aware engine walker)."""
    from autopsy.engine import AngrEngine

    assert 401 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_401():
    from autopsy.scope import resolve_checks

    assert resolve_checks("401") == [401]


def test_getenv_is_not_in_owned_allocators():
    """getenv/secure_getenv return libc-owned storage — never a leak."""
    from autopsy.engine import AngrEngine

    assert "getenv" not in AngrEngine._OWNED_ALLOCATORS
    assert "secure_getenv" not in AngrEngine._OWNED_ALLOCATORS
