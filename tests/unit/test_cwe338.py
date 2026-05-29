"""Fast unit tests for the CWE-338 weak-PRNG detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned CallSites, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe338
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


def test_no_findings_when_no_weak_prng_calls():
    """A program using only secure CSPRNG sources -> no findings."""
    engine = _make_engine(
        [_make_cs("getrandom"), _make_cs("arc4random"), _make_cs("arc4random_buf")]
    )
    assert cwe338.run(engine) == []


def test_rand_flagged_medium_confidence():
    """rand() is a predictable PRNG -> flagged at medium confidence."""
    engine = _make_engine([_make_cs("rand", call_address=0x401130)])
    findings = cwe338.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 338
    assert f.function == "main"
    assert f.address == 0x401130
    assert "rand" in f.evidence
    assert f.confidence == "medium"


def test_srand_seeder_flagged():
    """srand() seeds the predictable rand() stream -> flagged."""
    f = cwe338.run(_make_engine([_make_cs("srand")]))[0]
    assert f.cwe == 338
    assert f.confidence == "medium"
    assert "srand" in f.evidence


def test_random_flagged():
    """random() is reversible from a few outputs -> flagged."""
    f = cwe338.run(_make_engine([_make_cs("random")]))[0]
    assert f.cwe == 338
    assert "random" in f.evidence


def test_drand48_family_flagged():
    """The drand48 LCG family is trivially invertible -> flagged."""
    for name in ("drand48", "lrand48", "mrand48", "erand48", "nrand48", "jrand48"):
        f = cwe338.run(_make_engine([_make_cs(name)]))[0]
        assert f.cwe == 338
        assert name in f.evidence
        assert f.confidence == "medium"


def test_drand48_seeders_flagged():
    """srand48/seed48/lcong48 seed the predictable LCG -> flagged."""
    for name in ("srand48", "seed48", "lcong48"):
        f = cwe338.run(_make_engine([_make_cs(name)]))[0]
        assert f.cwe == 338
        assert name in f.evidence


def test_reentrant_variants_flagged():
    """The *_r reentrant variants are equally predictable -> flagged."""
    for name in ("rand_r", "random_r"):
        f = cwe338.run(_make_engine([_make_cs(name)]))[0]
        assert f.cwe == 338
        assert name in f.evidence


def test_secure_sources_never_flagged():
    """The CSPRNG sources must NOT fire (zero false positives)."""
    safe = ["getrandom", "arc4random", "arc4random_buf", "arc4random_uniform"]
    engine = _make_engine([_make_cs(name) for name in safe])
    assert cwe338.run(engine) == []


def test_multiple_weak_calls_each_flagged():
    """srand + rand + drand48 -> three distinct findings."""
    engine = _make_engine(
        [
            _make_cs("srand", caller_function="main", call_address=0x401130),
            _make_cs("rand", caller_function="main", call_address=0x401150),
            _make_cs("drand48", caller_function="main", call_address=0x401180),
        ]
    )
    findings = cwe338.run(engine)
    assert len(findings) == 3
    addrs = {f.address for f in findings}
    assert addrs == {0x401130, 0x401150, 0x401180}
    assert all(f.confidence == "medium" for f in findings)


def test_evidence_names_replacement():
    """Evidence steers the user to a secure CSPRNG replacement."""
    f = cwe338.run(_make_engine([_make_cs("rand")]))[0]
    assert "getrandom" in f.evidence or "arc4random" in f.evidence


def test_finding_has_one_taint_trace_point():
    """The 'taint trace' for a weak-PRNG use is the call site itself."""
    trace = cwe338.run(_make_engine([_make_cs("rand")]))[0].taint_trace
    assert len(trace) == 1
    assert "rand" in trace[0].description


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    d = cwe338.run(_make_engine([_make_cs("rand", call_address=0x401130)]))[0].to_dict()
    assert d["cwe"] == 338
    assert d["function"] == "main"
    assert d["address"] == "0x401130"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 1
    assert d["evidence"]
    assert d["confidence"] == "medium"


def test_cwe338_registered_in_checks():
    """CWE-338 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 338 in CHECKS
    assert CHECKS[338] is cwe338.run


def test_cwe338_in_scope_supported():
    """CWE-338 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 338 in SUPPORTED_CWES
    assert "338" in VALID_TOKENS


def test_cwe338_in_catalog():
    """CWE-338 must carry catalog metadata so --list-checks and SARIF name it."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 338 in CWE_CATALOG
    assert CWE_CATALOG[338]["short"] == "Weak PRNG"
    cat = {c["cwe"] for c in list_checks()}
    assert 338 in cat


def test_cwe338_is_arch_agnostic():
    """CWE-338 is call-site-driven, so it must run on AArch64 (not skipped)."""
    from autopsy.engine import AngrEngine

    assert 338 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_338():
    """resolve_checks('338') resolves to exactly [338]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("338") == [338]
