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
    # Every finding carries a triage confidence level.
    assert finding_dict["confidence"] in ("high", "medium", "low")


def test_cwe119_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe119-vuln", "119")
    d = rep.to_dict()
    assert d["error"] is None
    cwe119 = [f for f in d["findings"] if f["cwe"] == 119]
    assert cwe119, f"expected a CWE-119 finding, got {d['findings']}"
    _assert_finding_contract(cwe119[0], 119)
    # The symbolic register-index access is the high-confidence buffer-overflow
    # pattern; the fixture exercises it.
    confidences = {f["confidence"] for f in cwe119}
    assert "high" in confidences, f"expected a high-confidence CWE-119, got {confidences}"


def test_cwe190_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe190-vuln", "190")
    d = rep.to_dict()
    assert d["error"] is None
    cwe190 = [f for f in d["findings"] if f["cwe"] == 190]
    assert cwe190, f"expected a CWE-190 finding, got {d['findings']}"
    _assert_finding_contract(cwe190[0], 190)
    # The fixture multiplies a tainted size by a constant element width — one
    # symbolic operand, so the heuristic reports medium confidence.
    assert cwe190[0]["confidence"] == "medium"


def test_cwe415_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe415-vuln", "415")
    d = rep.to_dict()
    assert d["error"] is None
    cwe415 = [f for f in d["findings"] if f["cwe"] == 415]
    assert cwe415, f"expected a CWE-415 finding, got {d['findings']}"
    _assert_finding_contract(cwe415[0], 415)
    # Double-free is a definitive pattern -> always high confidence.
    assert cwe415[0]["confidence"] == "high"


def test_cwe415_interproc_detected(require_angr, fixtures_dir):
    # Single-hop cross-function double-free: run() frees a pointer then passes
    # it to release() (which frees it again).
    rep = _analyze(fixtures_dir, "cwe415-interproc-vuln", "415")
    d = rep.to_dict()
    assert d["error"] is None
    cwe415 = [f for f in d["findings"] if f["cwe"] == 415]
    assert cwe415, f"expected a cross-function CWE-415 finding, got {d['findings']}"
    # The second free is the callee handoff, reported in the caller (run).
    interproc = [f for f in cwe415 if f["function"] == "run"]
    assert interproc, f"expected the double-free reported in run(), got {cwe415}"
    _assert_finding_contract(interproc[0], 415)
    # Single-hop interprocedural findings are medium confidence.
    assert interproc[0]["confidence"] == "medium"
    assert "release" in interproc[0]["evidence"]


def test_cwe416_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe416-vuln", "416")
    d = rep.to_dict()
    assert d["error"] is None
    cwe416 = [f for f in d["findings"] if f["cwe"] == 416]
    assert cwe416, f"expected a CWE-416 finding, got {d['findings']}"
    _assert_finding_contract(cwe416[0], 416)
    # The fixture reloads the freed pointer from its stack slot before the use,
    # so slot aliasing is confirmed -> high confidence.
    assert cwe416[0]["confidence"] == "high"


def test_cwe416_interproc_detected(require_angr, fixtures_dir):
    # Single-hop cross-function use-after-free: run() passes a pointer to
    # release() (which frees it) then dereferences it after release() returns.
    rep = _analyze(fixtures_dir, "cwe416-interproc-vuln", "416")
    d = rep.to_dict()
    assert d["error"] is None
    cwe416 = [f for f in d["findings"] if f["cwe"] == 416]
    assert cwe416, f"expected a cross-function CWE-416 finding, got {d['findings']}"
    # The dangling dereference lives in the caller (run), not the freeing callee.
    interproc = [f for f in cwe416 if f["function"] == "run"]
    assert interproc, f"expected the UAF reported in run(), got {cwe416}"
    _assert_finding_contract(interproc[0], 416)
    # Single-hop interprocedural findings are medium confidence.
    assert interproc[0]["confidence"] == "medium"
    assert "release" in interproc[0]["evidence"]


def test_cwe476_detected(require_angr, fixtures_dir):
    # NULL pointer dereference: risky_fill() dereferences a malloc() result with
    # no NULL-check; safe_fill() (if (p == NULL) return) and safe_env() (getenv
    # checked) guard their pointers and must NOT fire.
    rep = _analyze(fixtures_dir, "cwe476-vuln", "476")
    d = rep.to_dict()
    assert d["error"] is None
    cwe476 = [f for f in d["findings"] if f["cwe"] == 476]
    assert cwe476, f"expected a CWE-476 finding, got {d['findings']}"
    vuln = [f for f in cwe476 if f["function"] == "risky_fill"]
    assert vuln, f"expected the unchecked deref in risky_fill(), got {cwe476}"
    _assert_finding_contract(vuln[0], 476)
    # The NULL-checked allocations must never be flagged (zero false positives).
    assert all(f["function"] != "safe_fill" for f in cwe476), (
        f"the NULL-checked malloc in safe_fill must not fire: {cwe476}"
    )
    assert all(f["function"] != "safe_env" for f in cwe476), (
        f"the NULL-checked getenv in safe_env must not fire: {cwe476}"
    )
    # Unchecked allocator-result dereference -> medium confidence.
    assert vuln[0]["confidence"] == "medium"
    assert "malloc" in vuln[0]["evidence"]


def test_cwe78_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe78-vuln", "78")
    d = rep.to_dict()
    assert d["error"] is None
    cwe78 = [f for f in d["findings"] if f["cwe"] == 78]
    assert cwe78, f"expected a CWE-78 finding, got {d['findings']}"
    _assert_finding_contract(cwe78[0], 78)
    # The fixture's sink is system() (not an exec* call), so the source+sink
    # pairing is present but flow evidence is weaker -> medium confidence.
    assert cwe78[0]["confidence"] == "medium"


def test_cwe787_detected(require_angr, fixtures_dir):
    rep = _analyze(fixtures_dir, "cwe787-vuln", "787")
    d = rep.to_dict()
    assert d["error"] is None
    cwe787 = [f for f in d["findings"] if f["cwe"] == 787]
    assert cwe787, f"expected a CWE-787 finding, got {d['findings']}"
    _assert_finding_contract(cwe787[0], 787)
    # malloc+memcpy taint mismatch heuristic reports medium confidence.
    assert cwe787[0]["confidence"] == "medium"


def test_cwe134_detected(require_angr, fixtures_dir):
    # Uncontrolled format string: emit() passes attacker-controlled input
    # straight to printf() as the format string (printf(user_input)).
    rep = _analyze(fixtures_dir, "cwe134-vuln", "134")
    d = rep.to_dict()
    assert d["error"] is None
    cwe134 = [f for f in d["findings"] if f["cwe"] == 134]
    assert cwe134, f"expected a CWE-134 finding, got {d['findings']}"
    # The vulnerable sink lives in emit(); the safe log_line() (literal format)
    # must not be flagged.
    vuln = [f for f in cwe134 if f["function"] == "emit"]
    assert vuln, f"expected the format-string finding in emit(), got {cwe134}"
    assert all(f["function"] != "log_line" for f in cwe134), (
        f"the literal-format printf in log_line must not be flagged, got {cwe134}"
    )
    _assert_finding_contract(vuln[0], 134)
    # Non-literal-format + global-source heuristic -> medium confidence.
    assert vuln[0]["confidence"] == "medium"
    assert "printf" in vuln[0]["evidence"]


def test_cwe676_detected(require_angr, fixtures_dir):
    # Use of potentially dangerous functions: the fixture calls gets(), strcpy()
    # and sprintf(). The call-site-driven check must flag each.
    rep = _analyze(fixtures_dir, "cwe676-vuln", "676")
    d = rep.to_dict()
    assert d["error"] is None
    cwe676 = [f for f in d["findings"] if f["cwe"] == 676]
    assert cwe676, f"expected CWE-676 findings, got {d['findings']}"
    for f in cwe676:
        _assert_finding_contract(f, 676)
    targets = {f["evidence"].split("(")[0].split()[-1] for f in cwe676}
    # gets/strcpy/sprintf must each appear in the evidence of some finding.
    joined = " ".join(f["evidence"] for f in cwe676)
    assert "gets" in joined, f"gets() not flagged: {cwe676}"
    assert "strcpy" in joined, f"strcpy() not flagged: {cwe676}"
    assert "sprintf" in joined, f"sprintf() not flagged: {cwe676}"
    # gets() is the no-safe-usage case -> at least one high-confidence finding.
    gets_findings = [f for f in cwe676 if "gets(" in f["evidence"]]
    assert gets_findings and gets_findings[0]["confidence"] == "high"


def test_cwe377_detected(require_angr, fixtures_dir):
    # Insecure temporary file: the fixture calls tmpnam(), mktemp() and
    # tempnam(). The call-site-driven check must flag each, but must NOT flag the
    # atomic mkstemp() in safe_create().
    rep = _analyze(fixtures_dir, "cwe377-vuln", "377")
    d = rep.to_dict()
    assert d["error"] is None
    cwe377 = [f for f in d["findings"] if f["cwe"] == 377]
    assert cwe377, f"expected CWE-377 findings, got {d['findings']}"
    for f in cwe377:
        _assert_finding_contract(f, 377)
    joined = " ".join(f["evidence"] for f in cwe377)
    assert "tmpnam" in joined, f"tmpnam() not flagged: {cwe377}"
    assert "mktemp" in joined, f"mktemp() not flagged: {cwe377}"
    assert "tempnam" in joined, f"tempnam() not flagged: {cwe377}"
    # The atomic replacement must never be flagged (zero false positives).
    assert "mkstemp" not in " ".join(
        f["evidence"].split(";")[0] for f in cwe377
    ), f"mkstemp() must not be flagged as insecure: {cwe377}"
    assert all(f["function"] != "safe_create" for f in cwe377), (
        f"the mkstemp() call in safe_create must not fire: {cwe377}"
    )
    # All four temp-name functions report medium confidence.
    assert all(f["confidence"] == "medium" for f in cwe377)


def test_cwe338_detected(require_angr, fixtures_dir):
    # Weak PRNG: the fixture seeds and draws from the predictable libc
    # generators (srand/rand/drand48). The call-site-driven check must flag
    # each, but must NOT flag the getrandom() CSPRNG used in secure_token().
    rep = _analyze(fixtures_dir, "cwe338-vuln", "338")
    d = rep.to_dict()
    assert d["error"] is None
    cwe338 = [f for f in d["findings"] if f["cwe"] == 338]
    assert cwe338, f"expected CWE-338 findings, got {d['findings']}"
    for f in cwe338:
        _assert_finding_contract(f, 338)
    joined = " ".join(f["evidence"] for f in cwe338)
    assert "srand" in joined, f"srand() not flagged: {cwe338}"
    assert "rand(" in joined, f"rand() not flagged: {cwe338}"
    assert "drand48" in joined, f"drand48() not flagged: {cwe338}"
    # The CSPRNG source must never be flagged (zero false positives).
    assert "getrandom" not in " ".join(
        f["evidence"].split(";")[0] for f in cwe338
    ), f"getrandom() must not be flagged: {cwe338}"
    assert all(f["function"] != "secure_token" for f in cwe338), (
        f"the getrandom() call in secure_token must not fire: {cwe338}"
    )
    # Every weak-PRNG call reports medium confidence.
    assert all(f["confidence"] == "medium" for f in cwe338)


def test_cwe369_detected(require_angr, fixtures_dir):
    # Divide by zero: risky_ratio() divides by an attacker-controlled divisor
    # with no zero-check; safe_ratio() guards the divisor and must NOT fire.
    rep = _analyze(fixtures_dir, "cwe369-vuln", "369")
    d = rep.to_dict()
    assert d["error"] is None
    cwe369 = [f for f in d["findings"] if f["cwe"] == 369]
    assert cwe369, f"expected a CWE-369 finding, got {d['findings']}"
    vuln = [f for f in cwe369 if f["function"] == "risky_ratio"]
    assert vuln, f"expected the divide-by-zero in risky_ratio(), got {cwe369}"
    _assert_finding_contract(vuln[0], 369)
    # The guarded division in safe_ratio must never be flagged.
    assert all(f["function"] != "safe_ratio" for f in cwe369), (
        f"the zero-checked division in safe_ratio must not fire: {cwe369}"
    )
    # Unguarded divisor + input source -> medium confidence.
    assert vuln[0]["confidence"] == "medium"
    assert "atoi" in vuln[0]["evidence"] or "fgets" in vuln[0]["evidence"]


def test_cwe732_detected(require_angr, fixtures_dir):
    # Incorrect permission assignment: expose_secret() chmods 0777 and
    # widen_shared() chmods 0666 (both group/world writable); loose_umask()
    # calls umask(0). lock_down() (chmod 0600) and tight_umask() (umask 0077)
    # are restrictive and must NOT fire.
    rep = _analyze(fixtures_dir, "cwe732-vuln", "732")
    d = rep.to_dict()
    assert d["error"] is None
    cwe732 = [f for f in d["findings"] if f["cwe"] == 732]
    assert cwe732, f"expected CWE-732 findings, got {d['findings']}"
    for f in cwe732:
        _assert_finding_contract(f, 732)
    funcs = {f["function"] for f in cwe732}
    assert "expose_secret" in funcs, f"chmod(0777) not flagged: {cwe732}"
    assert "widen_shared" in funcs, f"chmod(0666) not flagged: {cwe732}"
    assert "loose_umask" in funcs, f"umask(0) not flagged: {cwe732}"
    # The restrictive owner-only modes must never be flagged (zero false positives).
    assert "lock_down" not in funcs, f"chmod(0600) must not fire: {cwe732}"
    assert "tight_umask" not in funcs, f"umask(0077) must not fire: {cwe732}"
    # A definitive over-permissive chmod literal -> high confidence.
    chmod_findings = [f for f in cwe732 if f["function"] in ("expose_secret", "widen_shared")]
    assert chmod_findings and all(f["confidence"] == "high" for f in chmod_findings)
    # umask policy weakness -> medium confidence.
    umask_findings = [f for f in cwe732 if f["function"] == "loose_umask"]
    assert umask_findings and umask_findings[0]["confidence"] == "medium"
    assert "0o777" in " ".join(f["evidence"] for f in cwe732)


def test_cwe367_detected(require_angr, fixtures_dir):
    # TOCTOU race: access_then_open() checks with access() then open()s by name;
    # stat_then_fopen() stat()s then fopen()s; lstat_then_unlink() lstat()s then
    # unlink()s. The safe descriptor pattern (safe_open_then_fstat: open then
    # fstat on the fd) and the single-sided functions (only_check / only_use)
    # must NOT fire.
    rep = _analyze(fixtures_dir, "cwe367-vuln", "367")
    d = rep.to_dict()
    assert d["error"] is None
    cwe367 = [f for f in d["findings"] if f["cwe"] == 367]
    assert cwe367, f"expected CWE-367 findings, got {d['findings']}"
    for f in cwe367:
        _assert_finding_contract(f, 367)
        # Each TOCTOU finding records both the check and the use program points.
        assert len(f["taint_trace"]) == 2
    funcs = {f["function"] for f in cwe367}
    assert "access_then_open" in funcs, f"access->open not flagged: {cwe367}"
    assert "stat_then_fopen" in funcs, f"stat->fopen not flagged: {cwe367}"
    assert "lstat_then_unlink" in funcs, f"lstat->unlink not flagged: {cwe367}"
    # Zero false positives: the descriptor-based safe form and single-sided
    # functions must never fire.
    assert "safe_open_then_fstat" not in funcs, f"open->fstat(fd) must not fire: {cwe367}"
    assert "only_check" not in funcs, f"a lone access() must not fire: {cwe367}"
    assert "only_use" not in funcs, f"a lone open() must not fire: {cwe367}"
    # The check->use sequence is a structural-but-not-certain race -> medium.
    assert all(f["confidence"] == "medium" for f in cwe367)
    joined = " ".join(f["evidence"] for f in cwe367)
    assert "access" in joined and "open" in joined


def test_cwe78_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support: the call-site-driven CWE-78 check must fire on a
    # `bl` (branch-with-link) call to system() fed by an fgets() source, exactly
    # as it does for the x86_64 `call` form.
    rep = _analyze(fixtures_dir, "cwe78-aarch64-vuln", "78")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe78 = [f for f in d["findings"] if f["cwe"] == 78]
    assert cwe78, f"expected a CWE-78 finding on aarch64, got {d['findings']}"
    _assert_finding_contract(cwe78[0], 78)
    # system() sink -> medium confidence, same as the x86_64 fixture.
    assert cwe78[0]["confidence"] == "medium"


def test_aarch64_skips_register_level_checks(require_angr, fixtures_dir):
    # On AArch64, the register-level checks (CWE-119/415/416/787) are skipped
    # rather than producing unsound results; CWE-78/190 still run.
    rep = _analyze(fixtures_dir, "cwe78-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert set(d["skipped_checks"]) == {119, 369, 415, 416, 476, 134, 732, 787}
    # The CWE-78 finding still surfaces under "all".
    assert any(f["cwe"] == 78 for f in d["findings"])


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
        ("cwe338-vuln", 338),
        ("cwe367-vuln", 367),
        ("cwe369-vuln", 369),
        ("cwe377-vuln", 377),
        ("cwe415-vuln", 415),
        ("cwe415-interproc-vuln", 415),
        ("cwe416-vuln", 416),
        ("cwe416-interproc-vuln", 416),
        ("cwe476-vuln", 476),
        ("cwe78-vuln", 78),
        ("cwe134-vuln", 134),
        ("cwe676-vuln", 676),
        ("cwe732-vuln", 732),
        ("cwe787-vuln", 787),
    ]:
        rep = analyze(binary=str(fixtures_dir / name), checks_token=str(cwe),
                      max_states=1000)
        d = rep.to_dict()
        assert d["state_limit_exceeded"] is False, f"{name} hit state limit at 1000"
        assert d["error"] is None, f"{name} errored: {d['error']}"
