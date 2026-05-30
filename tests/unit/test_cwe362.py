"""Fast unit tests for the CWE-362 signal-handler race detector. angr-free.

These tests verify the check's detection logic using a mock engine that returns
pre-canned signal-handler/unsafe-call site dicts, with no angr dependency.
"""

from __future__ import annotations

from autopsy.checks import cwe362


def _site(
    handler="unsafe_handler",
    handler_address=0x401186,
    installer="signal",
    install_address=0x401264,
    unsafe_name="printf",
    unsafe_address=0x4011a5,
):
    return {
        "handler": handler,
        "handler_address": handler_address,
        "installer": installer,
        "install_address": install_address,
        "unsafe_name": unsafe_name,
        "unsafe_address": unsafe_address,
    }


def _make_engine(sites):
    class _E:
        def __init__(self):
            self._sites = sites

        def signal_handler_unsafe_calls(self):
            return list(self._sites)

    return _E()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sites():
    """No installed handlers / no unsafe calls -> no findings."""
    assert cwe362.run(_make_engine([])) == []


def test_printf_in_handler_flagged():
    """A handler calling printf -> CWE-362 finding anchored at the printf."""
    f = cwe362.run(_make_engine([_site(unsafe_name="printf", unsafe_address=0x4011a5)]))[0]
    assert f.cwe == 362
    assert f.function == "unsafe_handler"
    assert f.address == 0x4011a5
    assert "printf" in f.evidence
    assert "signal" in f.evidence
    assert f.confidence == "high"


def test_malloc_in_handler_flagged():
    """malloc is async-signal-unsafe (heap arena) -> flagged."""
    f = cwe362.run(_make_engine([_site(unsafe_name="malloc")]))[0]
    assert f.cwe == 362
    assert "malloc" in f.evidence


def test_free_in_handler_flagged():
    """free is async-signal-unsafe (heap arena reentrancy) -> flagged."""
    f = cwe362.run(_make_engine([_site(unsafe_name="free")]))[0]
    assert "free" in f.evidence


def test_exit_in_handler_flagged():
    """exit() runs atexit hooks and flushes stdio — flag it."""
    f = cwe362.run(_make_engine([_site(unsafe_name="exit")]))[0]
    assert "exit" in f.evidence


def test_sigset_alias_supported_as_installer():
    """The BSD `sigset` installer alias is recognized in the engine set."""
    from autopsy.engine import AngrEngine

    assert "sigset" in AngrEngine._SIGNAL_INSTALLERS
    assert "bsd_signal" in AngrEngine._SIGNAL_INSTALLERS
    assert "__sysv_signal" in AngrEngine._SIGNAL_INSTALLERS


def test_evidence_names_handler_and_installer():
    """Evidence text identifies both halves of the race (install + use)."""
    f = cwe362.run(_make_engine([
        _site(handler="on_sigterm", installer="signal", unsafe_name="syslog"),
    ]))[0]
    assert "on_sigterm" in f.evidence
    assert "signal" in f.evidence
    assert "syslog" in f.evidence


def test_remediation_hint_in_evidence():
    """Evidence suggests the canonical safe primitives."""
    f = cwe362.run(_make_engine([_site(unsafe_name="printf")]))[0]
    # The hint should mention either write() or _Exit() — the two canonical
    # async-signal-safe substitutes.
    assert "write()" in f.evidence or "_Exit" in f.evidence


def test_multiple_unsafe_calls_each_flagged():
    """Three unsafe calls in one handler -> three findings."""
    sites = [
        _site(unsafe_name="printf", unsafe_address=0x4011a5),
        _site(unsafe_name="malloc", unsafe_address=0x4011b0),
        _site(unsafe_name="free", unsafe_address=0x4011c0),
    ]
    findings = cwe362.run(_make_engine(sites))
    assert len(findings) == 3
    addrs = {f.address for f in findings}
    assert addrs == {0x4011a5, 0x4011b0, 0x4011c0}


def test_finding_has_two_taint_trace_points():
    """The trace shows the install site AND the unsafe-call site."""
    trace = cwe362.run(_make_engine([_site()]))[0].taint_trace
    assert len(trace) == 2
    assert "install" in trace[0].description.lower()
    assert "async-signal" in trace[1].description.lower()


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    d = cwe362.run(_make_engine([_site(unsafe_address=0x4011a5)]))[0].to_dict()
    assert d["cwe"] == 362
    assert d["function"] == "unsafe_handler"
    assert d["address"] == "0x4011a5"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "high"


def test_cwe362_registered_in_checks():
    """CWE-362 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 362 in CHECKS
    assert CHECKS[362] is cwe362.run


def test_cwe362_in_scope_supported():
    """CWE-362 must be in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 362 in SUPPORTED_CWES
    assert "362" in VALID_TOKENS


def test_cwe362_in_catalog():
    """CWE-362 must carry catalog metadata so --list-checks and SARIF name it."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 362 in CWE_CATALOG
    assert "Race" in CWE_CATALOG[362]["short"] or "Race" in CWE_CATALOG[362]["name"]
    cat = {c["cwe"] for c in list_checks()}
    assert 362 in cat


def test_cwe362_is_arch_agnostic():
    """CWE-362 must run on both supported architectures (x86_64 + AArch64)."""
    from autopsy.engine import AngrEngine

    assert 362 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_362():
    """resolve_checks('362') resolves to exactly [362]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("362") == [362]


def test_async_signal_unsafe_set_excludes_safe_primitives():
    """The async-unsafe set must NOT include the POSIX-safe primitives."""
    from autopsy.engine import AngrEngine

    # POSIX.1-2017 §2.4.3 explicitly safe primitives.
    safe = {"write", "read", "_exit", "_Exit", "signal", "raise", "kill",
            "sigaction", "sigprocmask", "open", "close"}
    for fn in safe:
        assert fn not in AngrEngine._ASYNC_SIGNAL_UNSAFE, (
            f"{fn} is POSIX async-signal-safe and must NOT be in the unsafe set"
        )


def test_async_signal_unsafe_set_includes_stdio_and_heap():
    """The unsafe set covers the canonical race-prone families."""
    from autopsy.engine import AngrEngine

    must_be_unsafe = {"printf", "fprintf", "puts", "fopen", "fclose",
                      "malloc", "free", "calloc", "realloc", "exit",
                      "syslog", "sprintf", "snprintf"}
    for fn in must_be_unsafe:
        assert fn in AngrEngine._ASYNC_SIGNAL_UNSAFE, (
            f"{fn} should be flagged as async-signal-unsafe"
        )
