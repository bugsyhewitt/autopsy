"""Fast unit tests for the CWE-125 heap OOB read detector. angr-free.

These tests verify the check's detection logic using a mock engine that
returns pre-canned CallSite objects, with no angr dependency. The check is
the read-side complement of CWE-787 and shares the same co-location +
literal-length-suppression shape.
"""

from __future__ import annotations

import pytest

from autopsy.checks import cwe125
from autopsy.engine import CallSite


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


def _make_engine(allocs, sources, reads, literal_lengths=None):
    """Build a mock engine with explicit per-category call-site lists.

    ``literal_lengths`` is an optional set of ``(function, address)`` tuples that
    the engine's ``copy_call_length_is_literal`` reports as literal-length
    reads (which the check must suppress). If ``literal_lengths`` is ``None``
    the mock engine does NOT expose ``copy_call_length_is_literal`` at all,
    exercising the backward-compatible path where the helper is absent.
    """

    class _E:
        def __init__(self):
            self._allocs = allocs
            self._sources = sources
            self._reads = reads

        def call_sites_to(self, names):
            alloc_names = {"malloc", "calloc", "realloc", "reallocarray"}
            source_names = {
                "fgets", "gets", "read", "scanf", "__isoc99_scanf",
                "atoi", "strtol", "atol",
            }
            read_names = {"memcmp", "strncmp", "strncasecmp", "memchr"}
            if names & alloc_names:
                return self._allocs
            if names & source_names:
                return self._sources
            if names & read_names:
                return self._reads
            return []

    eng = _E()
    if literal_lengths is not None:
        literal = set(literal_lengths)

        def copy_call_length_is_literal(function, address, sink_name):
            return (function, address) in literal

        eng.copy_call_length_is_literal = copy_call_length_is_literal
    return eng


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_allocators():
    """No allocator calls → no findings."""
    engine = _make_engine(
        allocs=[],
        sources=[_make_cs("atoi", call_address=0x400500)],
        reads=[_make_cs("memcmp", call_address=0x401100)],
    )
    assert cwe125.run(engine) == []


def test_no_findings_when_no_sources():
    """No input sources → no findings (no taint)."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", call_address=0x401000)],
        sources=[],
        reads=[_make_cs("memcmp", call_address=0x401100)],
    )
    assert cwe125.run(engine) == []


def test_no_findings_when_no_read_sinks():
    """No bulk-read calls → no findings."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", call_address=0x401000)],
        sources=[_make_cs("atoi", call_address=0x400500)],
        reads=[],
    )
    assert cwe125.run(engine) == []


def test_no_findings_when_alloc_and_read_in_different_functions():
    """malloc and memcmp in different functions → no finding."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="alloc_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="read_func", call_address=0x401100)],
    )
    assert cwe125.run(engine) == []


def test_finding_emitted_when_malloc_and_memcmp_collocated():
    """malloc + memcmp in same function + input source → one finding."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 125
    assert f.function == "vuln_func"
    assert f.address == 0x401100
    assert "malloc" in f.evidence
    assert "memcmp" in f.evidence


def test_finding_has_medium_confidence():
    """CWE-125 findings must carry confidence='medium'."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    assert findings[0].confidence == "medium"


def test_finding_has_three_taint_trace_points():
    """Taint trace must have three points: source, alloc, read."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    assert len(findings[0].taint_trace) == 3


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    d = cwe125.run(engine)[0].to_dict()
    assert d["cwe"] == 125
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
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1


def test_finding_per_independent_function():
    """Two separate functions each with malloc+read → two findings."""
    engine = _make_engine(
        allocs=[
            _make_cs("malloc", caller_function="func_a", call_address=0x401000),
            _make_cs("calloc", caller_function="func_b", call_address=0x402000),
        ],
        sources=[_make_cs("read", caller_function="main", call_address=0x400500)],
        reads=[
            _make_cs("memcmp", caller_function="func_a", call_address=0x401100),
            _make_cs("strncmp", caller_function="func_b", call_address=0x402100),
        ],
    )
    findings = cwe125.run(engine)
    assert len(findings) == 2
    funcs = {f.function for f in findings}
    assert funcs == {"func_a", "func_b"}


@pytest.mark.parametrize("read_sink", ["memcmp", "strncmp", "strncasecmp", "memchr"])
def test_all_supported_read_sinks_fire(read_sink):
    """Every member of _READ_SINKS should be recognized as a CWE-125 sink."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x400500)],
        reads=[_make_cs(read_sink, caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1
    assert read_sink in findings[0].evidence


def test_cwe125_registered_in_checks():
    """CWE-125 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS
    assert 125 in CHECKS
    assert CHECKS[125] is cwe125.run


def test_cwe125_in_scope_supported():
    """CWE-125 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS
    assert 125 in SUPPORTED_CWES
    assert "125" in VALID_TOKENS


def test_cwe125_in_catalog():
    """CWE-125 must have human-readable metadata in the canonical catalog."""
    from autopsy.scope import CWE_CATALOG
    assert 125 in CWE_CATALOG
    meta = CWE_CATALOG[125]
    assert meta["short"] == "Out-of-bounds Read"
    assert meta["uri"].endswith("/125.html")
    assert "Out-of-bounds Read" in meta["name"]


def test_taint_trace_source_description_mentions_function_name():
    """Taint trace point 0 must mention the input function name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    trace = findings[0].taint_trace
    assert "fgets" in trace[0].description


def test_taint_trace_alloc_description_mentions_allocator():
    """Taint trace point 1 must mention the allocator name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    trace = findings[0].taint_trace
    assert "malloc" in trace[1].description


def test_taint_trace_read_description_mentions_read_sink():
    """Taint trace point 2 must mention the read sink name."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
    )
    findings = cwe125.run(engine)
    trace = findings[0].taint_trace
    assert "memcmp" in trace[2].description


# ---------------------------------------------------------------------------
# Literal-length suppression (parity with CWE-787)
# ---------------------------------------------------------------------------


def test_literal_length_read_suppressed():
    """A read sink with a compile-time literal length must NOT be flagged.

    Mirror of the CWE-787 clean-baseline suppression: malloc(64) +
    memcmp(p, q, 4) is benign because the read extent is a fixed constant
    and cannot be tainted -> zero findings.
    """
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="main", call_address=0x4011dc)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x401191)],
        reads=[_make_cs("memcmp", caller_function="main", call_address=0x4011ff)],
        literal_lengths={("main", 0x4011ff)},
    )
    assert cwe125.run(engine) == []


def test_nonliteral_length_read_still_flagged():
    """A read sink with a non-literal (possibly-tainted) length still fires."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="read_from_heap", call_address=0x401188)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x401200)],
        reads=[_make_cs("memcmp", caller_function="read_from_heap", call_address=0x4012ec)],
        literal_lengths=set(),
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1
    assert findings[0].function == "read_from_heap"
    assert findings[0].confidence == "medium"


def test_function_with_only_literal_reads_suppressed_but_others_fire():
    """Per-function suppression: a literal-only function is dropped, others kept."""
    engine = _make_engine(
        allocs=[
            _make_cs("malloc", caller_function="safe_fn", call_address=0x1000),
            _make_cs("malloc", caller_function="vuln_fn", call_address=0x2000),
        ],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x500)],
        reads=[
            _make_cs("memcmp", caller_function="safe_fn", call_address=0x1100),
            _make_cs("strncmp", caller_function="vuln_fn", call_address=0x2100),
        ],
        literal_lengths={("safe_fn", 0x1100)},
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1
    assert findings[0].function == "vuln_fn"


def test_function_with_mixed_reads_fires_on_nonliteral():
    """A function with both a literal and a non-literal read still fires."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_fn", call_address=0x2000)],
        sources=[_make_cs("fgets", caller_function="main", call_address=0x500)],
        reads=[
            _make_cs("memcmp", caller_function="vuln_fn", call_address=0x2100),
            _make_cs("strncmp", caller_function="vuln_fn", call_address=0x2200),
        ],
        literal_lengths={("vuln_fn", 0x2100)},
    )
    findings = cwe125.run(engine)
    assert len(findings) == 1
    assert findings[0].function == "vuln_fn"
    # The reported read site is the non-literal one (the eligible sink).
    assert findings[0].address == 0x2200


def test_legacy_engine_without_helper_still_flags():
    """An engine lacking copy_call_length_is_literal keeps legacy behavior."""
    engine = _make_engine(
        allocs=[_make_cs("malloc", caller_function="vuln_func", call_address=0x401000)],
        sources=[_make_cs("atoi", caller_function="main", call_address=0x400500)],
        reads=[_make_cs("memcmp", caller_function="vuln_func", call_address=0x401100)],
        literal_lengths=None,  # helper absent
    )
    assert len(cwe125.run(engine)) == 1
