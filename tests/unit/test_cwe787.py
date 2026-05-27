"""Fast unit tests for the CWE-787 heap OOB write detector. angr-free.

These tests verify the check's detection logic using a mock engine that
returns pre-canned CallSite objects, with no angr dependency.
"""

from __future__ import annotations

import pytest

from autopsy.checks import cwe787
from autopsy.engine import CallSite
from autopsy.report import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cs(target_name, caller_function="vuln_func", call_address=0x401000, block_addr=0x401000):
    return CallSite(
        caller_function=caller_function,
        call_address=call_address,
        target_name=target_name,
        block_addr=block_addr,
    )


class MockCFG:
    pass


class MockEngine:
    """Minimal engine stub; call_sites_to returns canned lists."""

    def __init__(self, allocs, sources, copies):
        self._allocs = allocs
        self._sources = sources
        self._copies = copies

    def call_sites_to(self, names):
        result = []
        for cs_list, cs_names in (
            (self._allocs, {"malloc", "calloc", "realloc", "reallocarray"}),
            (self._sources, {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}),
            (self._copies, {"memcpy", "memmove", "strcpy", "strncpy", "memset", "bcopy"}),
        ):
            if names & cs_names:
                result.extend(cs_list)
        # Deduplicate based on the names set query.
        # Actually redo properly: return only matching lists.
        return result

    def cfg(self):
        return MockCFG()


def _make_engine(allocs, sources, copies):
    """Build a mock engine with explicit per-category call-site lists."""

    class _E:
        def __init__(self):
            self._allocs = allocs
            self._sources = sources
            self._copies = copies

        def call_sites_to(self, names):
            alloc_names = {"malloc", "calloc", "realloc", "reallocarray"}
            source_names = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}
            copy_names = {"memcpy", "memmove", "strcpy", "strncpy", "memset", "bcopy"}
            if names & alloc_names:
                return self._allocs
            if names & source_names:
                return self._sources
            if names & copy_names:
                return self._copies
            return []

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_allocators():
    """No allocator calls → no findings."""
    engine = _make_engine(
        allocs=[],
        sources=[_make_cs("atoi", call_address=0x400500)],
        copies=[_make_cs("memcpy", call_address=0x401100)],
    )
    assert cwe787.run(engine) == []


def test_no_findings_when_no_sources():
    """No input sources → no findings (no taint)."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", call_address=0x401000)],
        sources=[],
        copies=[_make_cs("memcpy", call_address=0x401100)],
    )
    assert cwe787.run(engine) == []


def test_no_findings_when_no_copy_sinks():
    """No bulk-copy calls → no findings."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", call_address=0x401000)],
        sources=[_make_cs("atoi", call_address=0x400500)],
        copies=[],
    )
    assert cwe787.run(engine) == []


def test_no_findings_when_alloc_and_copy_in_different_functions():
    """malloc and memcpy in different functions → no finding."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="alloc_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="copy_func", call_address=0x401100)],
    )
    assert cwe787.run(engine) == []


def test_finding_emitted_when_malloc_and_memcpy_collocated():
    """malloc + memcpy in same function + input source → one finding."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 787
    assert f.function == "vuln_func"
    assert f.address == 0x401100
    assert "malloc" in f.evidence
    assert "memcpy" in f.evidence


def test_finding_has_medium_confidence():
    """CWE-787 findings must carry confidence='medium'."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    assert findings[0].confidence == "medium"


def test_finding_has_three_taint_trace_points():
    """Taint trace must have three points: source, alloc, copy."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    assert len(findings[0].taint_trace) == 3


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    d = cwe787.run(engine)[0].to_dict()
    assert d["cwe"] == 787
    assert d["function"] == "vuln_func"
    assert d["address"] == "0x401100"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 3
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_one_finding_per_function():
    """Multiple malloc calls in same function → still one finding (not duplicated)."""
    engine = _make_engine(
        allocs=[
            _make_cs("malloc", caller_function="vuln_func", call_address=0x401000),
            _make_cs("malloc", caller_function="vuln_func", call_address=0x401050),
        ],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    assert len(findings) == 1


def test_finding_per_independent_function():
    """Two separate functions each with malloc+memcpy → two findings."""
    engine = _make_engine(
        allocs=[
            _make_cs("malloc", caller_function="func_a", call_address=0x401000),
            _make_cs("calloc", caller_function="func_b", call_address=0x402000),
        ],
        sources=[_make_cs("read", caller_function="main", call_address=0x400500)],
        copies=[
            _make_cs("memcpy", caller_function="func_a", call_address=0x401100),
            _make_cs("memmove", caller_function="func_b", call_address=0x402100),
        ],
    )
    findings = cwe787.run(engine)
    assert len(findings) == 2
    funcs = {f.function for f in findings}
    assert funcs == {"func_a", "func_b"}


def test_calloc_and_strcpy_detected():
    """calloc + strcpy is also a CWE-787 pattern."""
    engine = _make_engine(
        allocs=[_make_cs("calloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("gets", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("strcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    assert len(findings) == 1
    assert findings[0].cwe == 787


def test_cwe787_registered_in_checks():
    """CWE-787 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS
    assert 787 in CHECKS
    assert CHECKS[787] is cwe787.run


def test_cwe787_in_scope_supported():
    """CWE-787 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS
    assert 787 in SUPPORTED_CWES
    assert "787" in VALID_TOKENS


def test_taint_trace_source_description_mentions_function_name():
    """Taint trace point 0 must mention the input function name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    trace = findings[0].taint_trace
    assert "fgets" in trace[0].description


def test_taint_trace_alloc_description_mentions_allocator():
    """Taint trace point 1 must mention the allocator name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    trace = findings[0].taint_trace
    assert "malloc" in trace[1].description


def test_taint_trace_copy_description_mentions_copy_sink():
    """Taint trace point 2 must mention the copy sink name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        copies=[_make_cs("memcpy", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe787.run(engine)
    trace = findings[0].taint_trace
    assert "memcpy" in trace[2].description
