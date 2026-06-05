"""Fast unit tests for the CWE-78 OS command-injection detector. angr-free.

These tests verify the check's detection logic using a mock engine that
returns pre-canned CallSite lists for source/sink queries, with no angr
dependency.  The mock dispatch is keyed on the canonical sink/source name
sets the check defines.
"""

from __future__ import annotations

from autopsy.checks import cwe78
from autopsy.engine import CallSite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cs(
    target_name,
    caller_function: str = "main",
    call_address: int = 0x400500,
    block_addr: int = 0x400500,
) -> CallSite:
    return CallSite(
        caller_function=caller_function,
        call_address=call_address,
        target_name=target_name,
        block_addr=block_addr,
    )


def _make_engine(sinks=(), sources=()):
    """Mock engine: dispatch call_sites_to based on canonical name sets."""

    class _E:
        def call_sites_to(self, names):
            # Identify the query by a characteristic member of each set.
            if "system" in names or "popen" in names or "execve" in names:
                return list(sinks)
            if "fgets" in names or "read" in names or "recv" in names:
                return list(sources)
            return []

    return _E()


# ---------------------------------------------------------------------------
# Basic no-finding cases
# ---------------------------------------------------------------------------


def test_no_findings_when_no_sinks():
    """No command-sink calls -> no findings."""
    engine = _make_engine(sinks=[], sources=[_make_cs("fgets")])
    assert cwe78.run(engine) == []


def test_no_findings_when_no_input_source():
    """A sink present but no attacker-input source -> no finding."""
    engine = _make_engine(sinks=[_make_cs("system", call_address=0x4011aa)], sources=[])
    assert cwe78.run(engine) == []


# ---------------------------------------------------------------------------
# system() / popen() — medium confidence shell-interpolation sinks
# ---------------------------------------------------------------------------


def test_finding_emitted_for_system_with_source():
    """system() + input source -> one CWE-78 finding."""
    engine = _make_engine(
        sinks=[_make_cs("system", caller_function="do_cmd", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    findings = cwe78.run(engine)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 78
    assert f.function == "do_cmd"
    assert f.address == 0x4011aa
    assert "system" in f.evidence


def test_system_has_medium_confidence():
    """system() is a shell-interpolation sink -> medium confidence."""
    engine = _make_engine(
        sinks=[_make_cs("system", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "medium"


def test_popen_has_medium_confidence():
    """popen() uses a shell layer -> medium confidence."""
    engine = _make_engine(
        sinks=[_make_cs("popen", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "medium"


def test_wordexp_has_medium_confidence():
    """wordexp() expands through shell rules -> medium confidence."""
    engine = _make_engine(
        sinks=[_make_cs("wordexp", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "medium"


# ---------------------------------------------------------------------------
# exec* family — high confidence (no shell layer)
# ---------------------------------------------------------------------------


def test_execve_has_high_confidence():
    """execve() passes argv straight to kernel -> high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("execve", call_address=0x401200)],
        sources=[_make_cs("read")],
    )
    assert cwe78.run(engine)[0].confidence == "high"


def test_execl_has_high_confidence():
    """execl() is exec family -> high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("execl", call_address=0x401200)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "high"


def test_execlp_has_high_confidence():
    """execlp() is exec family -> high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("execlp", call_address=0x401200)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "high"


def test_execvp_has_high_confidence():
    """execvp() is exec family -> high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("execvp", call_address=0x401200)],
        sources=[_make_cs("fgets")],
    )
    assert cwe78.run(engine)[0].confidence == "high"


# ---------------------------------------------------------------------------
# R37 new sinks: execvpe, posix_spawn, posix_spawnp
# ---------------------------------------------------------------------------


def test_execvpe_detected_and_high_confidence():
    """execvpe() (GNU extension) is exec family -> detected, high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("execvpe", caller_function="launch", call_address=0x401300)],
        sources=[_make_cs("fgets")],
    )
    findings = cwe78.run(engine)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].function == "launch"


def test_posix_spawn_detected_and_high_confidence():
    """posix_spawn() spawns directly -> detected, high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("posix_spawn", caller_function="spawn_helper", call_address=0x401400)],
        sources=[_make_cs("recv")],
    )
    findings = cwe78.run(engine)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].function == "spawn_helper"


def test_posix_spawnp_detected_and_high_confidence():
    """posix_spawnp() resolves via PATH but no shell layer -> high confidence."""
    engine = _make_engine(
        sinks=[_make_cs("posix_spawnp", caller_function="run_tool", call_address=0x401500)],
        sources=[_make_cs("fgets")],
    )
    findings = cwe78.run(engine)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].function == "run_tool"


# ---------------------------------------------------------------------------
# Taint trace shape
# ---------------------------------------------------------------------------


def test_finding_has_two_taint_trace_points():
    """Taint trace: source point + sink point = 2 points."""
    engine = _make_engine(
        sinks=[_make_cs("system", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    trace = cwe78.run(engine)[0].taint_trace
    assert len(trace) == 2


def test_taint_trace_names_source_and_sink():
    """Trace point 0 names the source function; point 1 names the sink."""
    engine = _make_engine(
        sinks=[_make_cs("execve", call_address=0x4011aa)],
        sources=[_make_cs("read")],
    )
    trace = cwe78.run(engine)[0].taint_trace
    assert "read" in trace[0].description
    assert "execve" in trace[1].description


def test_taint_trace_addresses_match_call_sites():
    """Trace point addresses equal the call-site call_address values."""
    src_addr = 0x400600
    sink_addr = 0x401700
    engine = _make_engine(
        sinks=[_make_cs("system", call_address=sink_addr)],
        sources=[_make_cs("fgets", call_address=src_addr)],
    )
    trace = cwe78.run(engine)[0].taint_trace
    assert trace[0].address == src_addr
    assert trace[1].address == sink_addr


def test_earliest_source_used_as_taint_origin():
    """When multiple sources exist, the one with the lowest address is the origin."""
    engine = _make_engine(
        sinks=[_make_cs("system", call_address=0x4011aa)],
        sources=[
            _make_cs("read", call_address=0x400900),
            _make_cs("fgets", call_address=0x400500),
        ],
    )
    trace = cwe78.run(engine)[0].taint_trace
    assert trace[0].address == 0x400500
    assert "fgets" in trace[0].description


# ---------------------------------------------------------------------------
# Multiple sinks
# ---------------------------------------------------------------------------


def test_multiple_sinks_each_produce_a_finding():
    """Two distinct sink calls -> two findings."""
    engine = _make_engine(
        sinks=[
            _make_cs("system", caller_function="cmd_run", call_address=0x4011aa),
            _make_cs("execve", caller_function="cmd_exec", call_address=0x4012aa),
        ],
        sources=[_make_cs("fgets")],
    )
    findings = cwe78.run(engine)
    assert len(findings) == 2
    funcs = {f.function for f in findings}
    assert funcs == {"cmd_run", "cmd_exec"}


def test_mixed_confidence_sinks():
    """system() -> medium; execve() -> high in the same binary."""
    engine = _make_engine(
        sinks=[
            _make_cs("system", call_address=0x4011aa),
            _make_cs("execve", call_address=0x4012aa),
        ],
        sources=[_make_cs("fgets")],
    )
    findings = cwe78.run(engine)
    confidences = {f.confidence for f in findings}
    assert confidences == {"medium", "high"}


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_finding_serializes_correctly():
    """to_dict() produces the v0.1 contract fields including confidence."""
    engine = _make_engine(
        sinks=[_make_cs("system", caller_function="dispatch", call_address=0x4011aa)],
        sources=[_make_cs("fgets")],
    )
    d = cwe78.run(engine)[0].to_dict()
    assert d["cwe"] == 78
    assert d["function"] == "dispatch"
    assert d["address"] == "0x4011aa"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 2
    assert d["evidence"]
    assert d["confidence"] == "medium"


# ---------------------------------------------------------------------------
# Registry / scope integration
# ---------------------------------------------------------------------------


def test_cwe78_registered_in_checks():
    """CWE-78 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS
    assert 78 in CHECKS
    assert CHECKS[78] is cwe78.run


def test_cwe78_in_scope():
    """CWE-78 must be in SUPPORTED_CWES, VALID_TOKENS, and CWE_CATALOG."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS, CWE_CATALOG, resolve_checks
    assert 78 in SUPPORTED_CWES
    assert "78" in VALID_TOKENS
    assert 78 in CWE_CATALOG
    assert resolve_checks("78") == [78]
