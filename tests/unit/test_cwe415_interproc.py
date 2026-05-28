"""Fast unit tests for the single-hop interprocedural CWE-415 detector.

angr-free. The check's ``run()`` depends on three engine methods —
``in_binary_callees_freeing_arg``, ``callers_of``, and
``caller_frees_arg_before_call`` — which are mocked here with canned data. The
engine-level helper ``caller_frees_arg_before_call`` is exercised separately
against synthetic capstone-style instruction streams in
``test_engine_interproc.py``.
"""

from __future__ import annotations

from autopsy.checks import cwe415_interproc
from autopsy.engine import CallSite


# ---------------------------------------------------------------------------
# Mock engine
# ---------------------------------------------------------------------------


class MockEngine:
    """Engine stub returning canned interprocedural-analysis results.

    Args:
        freeing: set of in-binary function names that free their argument.
        callers: dict mapping callee name -> list of CallSite (its callers).
        frees: dict mapping (caller_name, call_address) -> first-free address
            or None.
    """

    def __init__(self, freeing=None, callers=None, frees=None):
        self._freeing = set(freeing or ())
        self._callers = callers or {}
        self._frees = frees or {}

    def in_binary_callees_freeing_arg(self):
        return set(self._freeing)

    def callers_of(self, name):
        return list(self._callers.get(name, []))

    def caller_frees_arg_before_call(self, caller_name, call_addr):
        return self._frees.get((caller_name, call_addr))


def _cs(callee, caller="run", call_address=0x401191, block_addr=0x401151):
    return CallSite(
        caller_function=caller,
        call_address=call_address,
        target_name=callee,
        block_addr=block_addr,
    )


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_no_findings_when_no_freeing_callees():
    engine = MockEngine(freeing=set())
    assert cwe415_interproc.run(engine) == []


def test_no_findings_when_callee_has_no_callers():
    engine = MockEngine(freeing={"release"}, callers={"release": []})
    assert cwe415_interproc.run(engine) == []


def test_no_findings_when_caller_did_not_free_first():
    # The caller passes the pointer to a freeing callee but never freed it
    # itself first — this is a normal single free, not a double-free.
    engine = MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x401191)]},
        frees={("run", 0x401191): None},
    )
    assert cwe415_interproc.run(engine) == []


def test_recursive_self_call_is_not_reported():
    # A function that calls itself is not an interprocedural single-hop case;
    # the intra-procedural pass handles same-function frees.
    engine = MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="release", call_address=0x401149)]},
        frees={("release", 0x401149): 0x401140},
    )
    assert cwe415_interproc.run(engine) == []


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------


def _vuln_engine():
    return MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x401191)]},
        frees={("run", 0x401191): 0x401185},
    )


def test_single_hop_double_free_detected():
    findings = cwe415_interproc.run(_vuln_engine())
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 415
    assert f.function == "run"
    # The finding is anchored at the second (callee-handoff) free call site.
    assert f.address == 0x401191


def test_finding_is_medium_confidence():
    f = cwe415_interproc.run(_vuln_engine())[0]
    assert f.confidence == "medium"


def test_finding_evidence_names_caller_and_callee():
    f = cwe415_interproc.run(_vuln_engine())[0]
    assert "run" in f.evidence
    assert "release" in f.evidence
    assert "double-free" in f.evidence


def test_taint_trace_has_two_points():
    f = cwe415_interproc.run(_vuln_engine())[0]
    trace = f.taint_trace
    assert len(trace) == 2
    # Point 0: the first free in the caller; point 1: the second free via callee.
    assert trace[0].address == 0x401185
    assert "free" in trace[0].description
    assert "double-free" in trace[1].description
    assert "release" in trace[1].description


def test_finding_serializes_to_contract():
    d = cwe415_interproc.run(_vuln_engine())[0].to_dict()
    assert d["cwe"] == 415
    assert d["function"] == "run"
    assert d["address"] == "0x401191"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_multiple_callers_each_reported():
    engine = MockEngine(
        freeing={"release"},
        callers={
            "release": [
                _cs("release", caller="func_a", call_address=0x401200),
                _cs("release", caller="func_b", call_address=0x401300),
            ]
        },
        frees={
            ("func_a", 0x401200): 0x4011f0,
            ("func_b", 0x401300): 0x4012f0,
        },
    )
    findings = cwe415_interproc.run(engine)
    assert {f.function for f in findings} == {"func_a", "func_b"}


def test_caller_that_freed_and_caller_that_did_not():
    engine = MockEngine(
        freeing={"release"},
        callers={
            "release": [
                _cs("release", caller="vuln", call_address=0x401200),
                _cs("release", caller="safe", call_address=0x401300),
            ]
        },
        frees={
            ("vuln", 0x401200): 0x4011f0,
            ("safe", 0x401300): None,  # safe caller never freed the pointer first
        },
    )
    findings = cwe415_interproc.run(engine)
    assert len(findings) == 1
    assert findings[0].function == "vuln"


def test_duplicate_call_sites_deduplicated():
    engine = MockEngine(
        freeing={"release"},
        callers={
            "release": [
                _cs("release", caller="run", call_address=0x401191),
                _cs("release", caller="run", call_address=0x401191),
            ]
        },
        frees={("run", 0x401191): 0x401185},
    )
    assert len(cwe415_interproc.run(engine)) == 1


# ---------------------------------------------------------------------------
# Integration with the registered CWE-415 check
# ---------------------------------------------------------------------------


class _EmptyFuncs:
    def values(self):
        return []


class _EmptyKB:
    functions = _EmptyFuncs()


class _EmptyCfg:
    kb = _EmptyKB()


class _MergeEngine(MockEngine):
    """Adds the cfg() interface the intra-procedural pass needs (empty CFG)."""

    def cfg(self):
        return _EmptyCfg()


def test_registered_cwe415_includes_interproc_findings():
    from autopsy.checks import cwe415

    engine = _MergeEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x401191)]},
        frees={("run", 0x401191): 0x401185},
    )
    findings = cwe415.run(engine)
    # The intra pass finds nothing (empty CFG); the interproc finding surfaces.
    assert len(findings) == 1
    assert findings[0].function == "run"
    assert findings[0].address == 0x401191
