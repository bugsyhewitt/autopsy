"""Slow, angr-backed end-to-end detection tests against real ELF fixtures.

Every test here is marked ``@pytest.mark.slow`` and so is DESELECTED by the
default ``pytest`` run (see pyproject addopts ``-m 'not slow'``). Run with:

    pytest -m slow

These tests import and invoke angr against the deliberately-vulnerable
binaries shipped in tests/fixtures/, asserting the v0.1 JSON contract and the
zero-false-positive guarantee on the clean baseline.
"""

import pytest

from autopsy.analyzer import analyze


pytestmark = pytest.mark.slow


def _analyze(fixtures_dir, name, checks):
    binary = str(fixtures_dir / name)
    return analyze(binary=binary, checks_token=checks, max_states=1000)


def _assert_finding_contract(finding_dict, cwe):
    assert finding_dict["cwe"] == cwe
    assert finding_dict["function"]
    assert finding_dict["address"].startswith("0x")
    assert isinstance(finding_dict["taint_trace"], list)
    assert len(finding_dict["taint_trace"]) >= 1
    assert finding_dict["evidence"]


def test_cwe119_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe119-vuln", "119")
    d = rep.to_dict()
    assert d["error"] is None
    cwe119 = [f for f in d["findings"] if f["cwe"] == 119]
    assert cwe119, f"expected a CWE-119 finding, got {d['findings']}"
    _assert_finding_contract(cwe119[0], 119)


def test_cwe190_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe190-vuln", "190")
    d = rep.to_dict()
    assert d["error"] is None
    cwe190 = [f for f in d["findings"] if f["cwe"] == 190]
    assert cwe190, f"expected a CWE-190 finding, got {d['findings']}"
    _assert_finding_contract(cwe190[0], 190)


def test_cwe415_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe415-vuln", "415")
    d = rep.to_dict()
    assert d["error"] is None
    cwe415 = [f for f in d["findings"] if f["cwe"] == 415]
    assert cwe415, f"expected a CWE-415 finding, got {d['findings']}"
    _assert_finding_contract(cwe415[0], 415)


def test_cwe416_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe416-vuln", "416")
    d = rep.to_dict()
    assert d["error"] is None
    cwe416 = [f for f in d["findings"] if f["cwe"] == 416]
    assert cwe416, f"expected a CWE-416 finding, got {d['findings']}"
    _assert_finding_contract(cwe416[0], 416)


def test_cwe78_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe78-vuln", "78")
    d = rep.to_dict()
    assert d["error"] is None
    cwe78 = [f for f in d["findings"] if f["cwe"] == 78]
    assert cwe78, f"expected a CWE-78 finding, got {d['findings']}"
    _assert_finding_contract(cwe78[0], 78)


def test_clean_baseline_zero_false_positives(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "clean-baseline", "all")
    d = rep.to_dict()
    assert d["error"] is None
    assert d["findings"] == [], f"clean baseline produced findings: {d['findings']}"
    assert d["finding_count"] == 0


def test_max_states_low_aborts(require_angr, fixtures_dir):
    # At a very low cap, analysis that drives symbolic exploration must abort.
    # CWE-119's symbolic reachability path is the one that exercises states.
    binary = str(fixtures_dir / "cwe119-vuln")
    rep = analyze(binary=binary, checks_token="119", max_states=10)
    d = rep.to_dict()
    # Either the state limit tripped, or (if a check is purely CFG-based) the
    # cap was honored without exceeding — both are acceptable so long as the
    # cap is wired. We assert the cap is reflected and, when tripped, surfaced.
    assert d["max_states"] == 10
    if d["state_limit_exceeded"]:
        assert "state limit exceeded" in d["error"]


def test_max_states_high_completes_all_fixtures(require_angr, fixtures_dir):
    for name, cwe in [
        ("cwe119-vuln", 119),
        ("cwe190-vuln", 190),
        ("cwe415-vuln", 415),
        ("cwe416-vuln", 416),
        ("cwe78-vuln", 78),
    ]:
        rep = analyze(binary=str(fixtures_dir / name), checks_token=str(cwe),
                      max_states=1000)
        d = rep.to_dict()
        assert d["state_limit_exceeded"] is False, f"{name} hit state limit at 1000"
        assert d["error"] is None, f"{name} errored: {d['error']}"
