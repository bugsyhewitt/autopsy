"""Fast unit tests for the single-hop interprocedural CWE-416 detector.

angr-free. The check's ``run()`` depends on three engine methods —
``in_binary_callees_freeing_arg``, ``callers_of``, and
``caller_uses_arg_after_call`` — which are mocked here with canned data. The
engine-level helpers themselves are exercised separately against synthetic
capstone-style instruction streams in ``test_engine_interproc.py``.
"""

from __future__ import annotations

from autopsy.checks import cwe416_interproc
from autopsy.engine import CallSite


# ---------------------------------------------------------------------------
# Mock engine
# ---------------------------------------------------------------------------


class MockEngine:
    """Engine stub returning canned interprocedural-analysis results.

    Args:
        freeing: set of in-binary function names that free their argument.
        callers: dict mapping callee name -> list of CallSite (its callers).
        uses: dict mapping (caller_name, call_address) -> use address or None.
    """

    def __init__(self, freeing=None, callers=None, uses=None):
        self._freeing = set(freeing or ())
        self._callers = callers or {}
        self._uses = uses or {}

    def in_binary_callees_freeing_arg(self):
        return set(self._freeing)

    def callers_of(self, name):
        return list(self._callers.get(name, []))

    def caller_uses_arg_after_call(self, caller_name, call_addr):
        return self._uses.get((caller_name, call_addr))


def _cs(callee, caller="run", call_address=0x40118a, block_addr=0x401151):
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
    assert cwe416_interproc.run(engine) == []


def test_no_findings_when_callee_has_no_callers():
    engine = MockEngine(freeing={"release"}, callers={"release": []})
    assert cwe416_interproc.run(engine) == []


def test_no_findings_when_caller_does_not_use_after_call():
    # The caller passes the pointer to a freeing callee but never derefs it.
    engine = MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x40118a)]},
        uses={("run", 0x40118a): None},
    )
    assert cwe416_interproc.run(engine) == []


def test_recursive_self_call_is_not_reported():
    # A function that calls itself is not an interprocedural single-hop case;
    # the intra-procedural pass handles same-function frees.
    engine = MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="release", call_address=0x401149)]},
        uses={("release", 0x401149): 0x40114e},
    )
    assert cwe416_interproc.run(engine) == []


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------


def _vuln_engine():
    return MockEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x40118a)]},
        uses={("run", 0x40118a): 0x401193},
    )


def test_single_hop_uaf_detected():
    findings = cwe416_interproc.run(_vuln_engine())
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 416
    assert f.function == "run"
    assert f.address == 0x401193


def test_finding_is_medium_confidence():
    f = cwe416_interproc.run(_vuln_engine())[0]
    assert f.confidence == "medium"


def test_finding_evidence_names_caller_and_callee():
    f = cwe416_interproc.run(_vuln_engine())[0]
    assert "run" in f.evidence
    assert "release" in f.evidence


def test_taint_trace_has_two_points():
    f = cwe416_interproc.run(_vuln_engine())[0]
    trace = f.taint_trace
    assert len(trace) == 2
    # Point 0: the free at the call site; point 1: the use in the caller.
    assert "release" in trace[0].description
    assert "use-after-free" in trace[1].description


def test_finding_serializes_to_contract():
    d = cwe416_interproc.run(_vuln_engine())[0].to_dict()
    assert d["cwe"] == 416
    assert d["function"] == "run"
    assert d["address"] == "0x401193"
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
        uses={
            ("func_a", 0x401200): 0x401210,
            ("func_b", 0x401300): 0x401310,
        },
    )
    findings = cwe416_interproc.run(engine)
    assert {f.function for f in findings} == {"func_a", "func_b"}


def test_caller_that_uses_and_caller_that_does_not():
    engine = MockEngine(
        freeing={"release"},
        callers={
            "release": [
                _cs("release", caller="vuln", call_address=0x401200),
                _cs("release", caller="safe", call_address=0x401300),
            ]
        },
        uses={
            ("vuln", 0x401200): 0x401210,
            ("safe", 0x401300): None,  # safe caller does not reuse the pointer
        },
    )
    findings = cwe416_interproc.run(engine)
    assert len(findings) == 1
    assert findings[0].function == "vuln"


def test_duplicate_call_sites_deduplicated():
    engine = MockEngine(
        freeing={"release"},
        callers={
            "release": [
                _cs("release", caller="run", call_address=0x40118a),
                _cs("release", caller="run", call_address=0x40118a),
            ]
        },
        uses={("run", 0x40118a): 0x401193},
    )
    assert len(cwe416_interproc.run(engine)) == 1


# ---------------------------------------------------------------------------
# Integration with the registered CWE-416 check
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


def test_registered_cwe416_includes_interproc_findings():
    from autopsy.checks import cwe416

    engine = _MergeEngine(
        freeing={"release"},
        callers={"release": [_cs("release", caller="run", call_address=0x40118a)]},
        uses={("run", 0x40118a): 0x401193},
    )
    findings = cwe416.run(engine)
    # The intra pass finds nothing (empty CFG); the interproc finding surfaces.
    assert len(findings) == 1
    assert findings[0].function == "run"
    assert findings[0].address == 0x401193
