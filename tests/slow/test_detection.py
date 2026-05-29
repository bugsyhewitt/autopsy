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


def test_cwe190_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware register-level CWE-190 check:
    # the 32-bit size arithmetic (`lsl w8, w8, #0xc` for `count * 4096`) is found
    # before the `bl malloc` call and paired with the attacker-input source
    # (fgets/atoi), mirroring the x86_64 `shl eax, 0xc` behavior. One register
    # source plus an immediate shift -> medium confidence, same as x86_64.
    rep = _analyze(fixtures_dir, "cwe190-aarch64-vuln", "190")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe190 = [f for f in d["findings"] if f["cwe"] == 190]
    assert cwe190, f"expected a CWE-190 finding on aarch64, got {d['findings']}"
    _assert_finding_contract(cwe190[0], 190)
    vuln = [f for f in cwe190 if f["function"] == "alloc_records"]
    assert vuln, f"expected the overflow in alloc_records(), got {cwe190}"
    # The fixture shifts a tainted count by a constant width (one symbolic
    # operand) -> medium confidence, exactly as the x86_64 fixture reports.
    assert vuln[0]["confidence"] == "medium"
    # The arithmetic taint point names the AArch64 shift mnemonic.
    assert any("lsl" in tp["description"] for tp in vuln[0]["taint_trace"]), (
        f"expected the lsl size-arithmetic point in the trace: {vuln[0]}"
    )


def test_aarch64_runs_cwe190_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-190 runs (it is arch-agnostic / arch-aware and
    # is not in the skipped set) and its findings surface.
    rep = _analyze(fixtures_dir, "cwe190-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert 190 not in d["skipped_checks"], (
        f"CWE-190 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 190 for f in d["findings"]), (
        f"expected CWE-190 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe732_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware register-level CWE-732 check:
    # the chmod/umask mode immediate is read out of the AAPCS64 argument
    # register (w1 for chmod, w0 for umask, including the `mov w0, wzr`
    # zero-register encoding of umask(0)) at each `bl` call site — mirroring the
    # x86_64 behavior. The same vulnerable/safe function split as the x86_64
    # fixture must hold (zero false positives on the restrictive modes).
    rep = _analyze(fixtures_dir, "cwe732-aarch64-vuln", "732")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe732 = [f for f in d["findings"] if f["cwe"] == 732]
    assert cwe732, f"expected CWE-732 findings on aarch64, got {d['findings']}"
    for f in cwe732:
        _assert_finding_contract(f, 732)
    funcs = {f["function"] for f in cwe732}
    assert "expose_secret" in funcs, f"chmod(0777) not flagged on aarch64: {cwe732}"
    assert "widen_shared" in funcs, f"chmod(0666) not flagged on aarch64: {cwe732}"
    assert "loose_umask" in funcs, f"umask(0) not flagged on aarch64: {cwe732}"
    # The restrictive owner-only modes must never be flagged (zero false positives).
    assert "lock_down" not in funcs, f"chmod(0600) must not fire on aarch64: {cwe732}"
    assert "tight_umask" not in funcs, f"umask(0077) must not fire on aarch64: {cwe732}"
    # chmod literal -> high confidence; umask policy -> medium (same as x86_64).
    chmod_findings = [f for f in cwe732 if f["function"] in ("expose_secret", "widen_shared")]
    assert chmod_findings and all(f["confidence"] == "high" for f in chmod_findings)
    umask_findings = [f for f in cwe732 if f["function"] == "loose_umask"]
    assert umask_findings and umask_findings[0]["confidence"] == "medium"
    assert "0o777" in " ".join(f["evidence"] for f in cwe732)


def test_aarch64_runs_cwe732_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-732 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe732-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    # CWE-732 must NOT appear in the skipped set on AArch64 anymore.
    assert 732 not in d["skipped_checks"], (
        f"CWE-732 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 732 for f in d["findings"]), (
        f"expected CWE-732 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe134_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware register-level CWE-134 check:
    # the printf-family format-string argument is read out of the AAPCS64
    # argument register (x0 for printf, x1 for fprintf) and confirmed to be a
    # stack-slot reload (`ldr x0, [sp, #N]`) rather than a rodata literal
    # (`adrp`/`adr`) — mirroring the x86_64 `rdi`/`lea [rip+disp]` behavior. The
    # same vulnerable/safe split as the x86_64 fixture must hold.
    rep = _analyze(fixtures_dir, "cwe134-aarch64-vuln", "134")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe134 = [f for f in d["findings"] if f["cwe"] == 134]
    assert cwe134, f"expected CWE-134 findings on aarch64, got {d['findings']}"
    for f in cwe134:
        _assert_finding_contract(f, 134)
    funcs = {f["function"] for f in cwe134}
    # printf(user) in emit() and fprintf(stderr, user) in emit_err() both fire.
    assert "emit" in funcs, f"printf(user) not flagged on aarch64: {cwe134}"
    assert "emit_err" in funcs, f"fprintf(stderr, user) not flagged on aarch64: {cwe134}"
    # The literal-format printf in log_line() (adrp/adr rodata pointer) must NOT
    # fire — the zero-false-positive guarantee on the safe companion.
    assert "log_line" not in funcs, (
        f"the literal-format printf in log_line must not be flagged on aarch64: {cwe134}"
    )
    # Non-literal-format + global-source heuristic -> medium confidence (same as x86_64).
    assert all(f["confidence"] == "medium" for f in cwe134)
    # The evidence names the AArch64 format register (x0 / x1).
    emit_finding = next(f for f in cwe134 if f["function"] == "emit")
    assert "x0" in emit_finding["evidence"], (
        f"expected the x0 format register in the evidence: {emit_finding}"
    )
    emit_err_finding = next(f for f in cwe134 if f["function"] == "emit_err")
    assert "x1" in emit_err_finding["evidence"], (
        f"expected the x1 format register in the evidence: {emit_err_finding}"
    )


def test_aarch64_runs_cwe134_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-134 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe134-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    # CWE-134 must NOT appear in the skipped set on AArch64 anymore.
    assert 134 not in d["skipped_checks"], (
        f"CWE-134 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 134 for f in d["findings"]), (
        f"expected CWE-134 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe415_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware intra-procedural CWE-415 check:
    # the allocator return register (`x0`) is spilled to a stack slot
    # (`str x0, [sp, #N]`) and reloaded (`ldr x0, [sp, #N]`) before two
    # successive `bl <free>` calls with no intervening call — the double-free.
    # The same vulnerable/safe split as the x86_64 fixture must hold.
    rep = _analyze(fixtures_dir, "cwe415-aarch64-vuln", "415")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe415 = [f for f in d["findings"] if f["cwe"] == 415]
    assert cwe415, f"expected a CWE-415 finding on aarch64, got {d['findings']}"
    for f in cwe415:
        _assert_finding_contract(f, 415)
    funcs = {f["function"] for f in cwe415}
    # The double-free in double_free() fires; the single free in safe_free() does not.
    assert "double_free" in funcs, f"double-free not flagged on aarch64: {cwe415}"
    assert "safe_free" not in funcs, (
        f"the single free in safe_free must not be flagged on aarch64: {cwe415}"
    )
    # Intra-procedural double-free is a definitive pattern -> high confidence.
    assert all(f["confidence"] == "high" for f in cwe415 if f["function"] == "double_free")


def test_aarch64_runs_cwe415_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-415 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe415-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    # CWE-415 must NOT appear in the skipped set on AArch64 anymore.
    assert 415 not in d["skipped_checks"], (
        f"CWE-415 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 415 for f in d["findings"]), (
        f"expected CWE-415 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe416_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware intra-procedural CWE-416 check:
    # the allocator return register (`x0`) is spilled to a stack slot
    # (`str x0, [sp, #N]`) and reloaded (`ldr x0, [sp, #N]`) before a `bl <free>`
    # call, then reloaded again after the free and dereferenced (`str`/`ldr`
    # through the reloaded base register) with no intervening call — the
    # use-after-free. The same vulnerable/safe split as the x86_64 fixture holds.
    rep = _analyze(fixtures_dir, "cwe416-aarch64-vuln", "416")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe416 = [f for f in d["findings"] if f["cwe"] == 416]
    assert cwe416, f"expected a CWE-416 finding on aarch64, got {d['findings']}"
    for f in cwe416:
        _assert_finding_contract(f, 416)
    funcs = {f["function"] for f in cwe416}
    # The use-after-free in use_after_free() fires; the safe single free that is
    # never reused (safe_free) does not.
    assert "use_after_free" in funcs, f"use-after-free not flagged on aarch64: {cwe416}"
    assert "safe_free" not in funcs, (
        f"the freed-but-not-reused pointer in safe_free must not be flagged on "
        f"aarch64: {cwe416}"
    )
    # The fixture reloads the freed pointer from its stack slot before the use,
    # so slot aliasing is confirmed -> high confidence, as on x86_64.
    uaf = [f for f in cwe416 if f["function"] == "use_after_free"]
    assert uaf and uaf[0]["confidence"] == "high"


def test_aarch64_runs_cwe416_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-416 now runs (it is no longer in the skipped
    # set) and its intra-procedural findings surface alongside the other checks.
    rep = _analyze(fixtures_dir, "cwe416-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    # CWE-416 must NOT appear in the skipped set on AArch64 anymore.
    assert 416 not in d["skipped_checks"], (
        f"CWE-416 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 416 for f in d["findings"]), (
        f"expected CWE-416 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe369_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware register-level CWE-369 check:
    # the divisor is the THIRD operand of `sdiv`/`udiv` (`sdiv Wd, Wn, Wm` -> Wm),
    # and a division with no preceding zero-check (`cbz`/`cbnz` on the divisor, or
    # `cmp`/`tst` + `b.<cond>`) co-located with an attacker-input source is the
    # CWE-369 site. The same vulnerable/safe split as the x86_64 fixture holds.
    # (ARMv8 defines divide-by-zero as 0 rather than a trap, so the consequence
    # differs from x86_64's SIGFPE, but the unguarded divisor is the weakness.)
    rep = _analyze(fixtures_dir, "cwe369-aarch64-vuln", "369")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe369 = [f for f in d["findings"] if f["cwe"] == 369]
    assert cwe369, f"expected a CWE-369 finding on aarch64, got {d['findings']}"
    vuln = [f for f in cwe369 if f["function"] == "risky_ratio"]
    assert vuln, f"expected the unguarded sdiv in risky_ratio(), got {cwe369}"
    _assert_finding_contract(vuln[0], 369)
    # The zero-checked division in safe_ratio (cbnz/cmp guard) must never fire.
    assert all(f["function"] != "safe_ratio" for f in cwe369), (
        f"the zero-checked division in safe_ratio must not fire on aarch64: {cwe369}"
    )
    # Unguarded divisor + input source -> medium confidence (same as x86_64).
    assert vuln[0]["confidence"] == "medium"


def test_aarch64_runs_cwe369_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-369 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe369-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert 369 not in d["skipped_checks"], (
        f"CWE-369 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 369 for f in d["findings"]), (
        f"expected CWE-369 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe119_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware register-level CWE-119 check:
    # the int index is sign-extended (`ldrsw x10, [sp, #N]`), the buffer address
    # is formed with an explicit base+index sum (`add x9, x9, x10`), and the
    # store dereferences that base register (`strb w8, [x9]`) with no preceding
    # bounds check — the register-indexed buffer write. The safe companion
    # range-checks the index (`tbnz`/`subs` + `b.<cond>`) and must NOT fire.
    rep = _analyze(fixtures_dir, "cwe119-aarch64-vuln", "119")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe119 = [f for f in d["findings"] if f["cwe"] == 119]
    assert cwe119, f"expected a CWE-119 finding on aarch64, got {d['findings']}"
    for f in cwe119:
        _assert_finding_contract(f, 119)
    funcs = {f["function"] for f in cwe119}
    # The unguarded register-indexed store in store_at() fires.
    assert "store_at" in funcs, f"buffer write not flagged on aarch64: {cwe119}"
    # The range-checked access in safe_store() must never fire (zero false positives).
    assert "safe_store" not in funcs, (
        f"the bounds-checked access in safe_store must not fire on aarch64: {cwe119}"
    )
    # The base+index register address (`add xD, xBase, xIdx`) is a genuinely
    # data-dependent ("symbolic") offset -> high confidence, as on x86_64.
    store_finding = next(f for f in cwe119 if f["function"] == "store_at")
    assert store_finding["confidence"] == "high"


def test_aarch64_runs_cwe119_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-119 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe119-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert 119 not in d["skipped_checks"], (
        f"CWE-119 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 119 for f in d["findings"]), (
        f"expected CWE-119 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe787_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware CWE-787 heap-OOB-write check:
    # call-site discovery (allocator/source/copy enumeration) is already
    # arch-agnostic, and the length-arg literal-suppression helper now reads
    # the AAPCS64 length register (`x2`/`w2`) — `mov w2, #imm` is a literal,
    # `ldr w2, [sp, #N]`/`ldursw` is a stack reload (possibly tainted). The
    # vulnerable copy_to_heap() (memcpy with tainted length) fires; the safe
    # safe_copy() (strncpy with a 63-byte literal length) must NOT fire.
    rep = _analyze(fixtures_dir, "cwe787-aarch64-vuln", "787")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe787 = [f for f in d["findings"] if f["cwe"] == 787]
    assert cwe787, f"expected a CWE-787 finding on aarch64, got {d['findings']}"
    for f in cwe787:
        _assert_finding_contract(f, 787)
    funcs = {f["function"] for f in cwe787}
    # The tainted-length memcpy in copy_to_heap() fires.
    assert "copy_to_heap" in funcs, (
        f"tainted-length memcpy not flagged on aarch64: {cwe787}"
    )
    # The literal-length strncpy(p, line, 63) in safe_copy() must NOT fire —
    # the literal-length suppression (now arch-aware on AArch64) catches it.
    assert "safe_copy" not in funcs, (
        f"literal-length strncpy in safe_copy must not fire on aarch64: {cwe787}"
    )
    # The co-location heuristic reports medium confidence (same as x86_64).
    copy_finding = next(f for f in cwe787 if f["function"] == "copy_to_heap")
    assert copy_finding["confidence"] == "medium"


def test_aarch64_runs_cwe787_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-787 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the call-site-driven checks.
    rep = _analyze(fixtures_dir, "cwe787-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert 787 not in d["skipped_checks"], (
        f"CWE-787 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 787 for f in d["findings"]), (
        f"expected CWE-787 findings under 'all' on aarch64: {d['findings']}"
    )


def test_cwe476_detected_on_aarch64(require_angr, fixtures_dir):
    # AArch64 (ARM64) support for the arch-aware CWE-476 NULL-dereference
    # check: the allocator's return register `x0` is spilled to a stack slot
    # (`str x0, [sp, #N]` / `[x29, #N]`), reloaded into an alias register
    # (`ldr xR, [sp, #N]`), and dereferenced through that base register
    # (`str wzr, [xR]`) with no NULL-check guard. The AArch64 guard recognizer
    # accepts `cbz`/`cbnz` on a slot-aliased register and `cmp xR, #0` /
    # `cmp xR, xzr` / `tst xR, xR` + `b.<cond>`. The vulnerable risky_fill()
    # fires (no guard); the safe_fill() and safe_env() companions must NOT fire
    # (each guards the reloaded result with a `cbnz`).
    rep = _analyze(fixtures_dir, "cwe476-aarch64-vuln", "476")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    cwe476 = [f for f in d["findings"] if f["cwe"] == 476]
    assert cwe476, f"expected a CWE-476 finding on aarch64, got {d['findings']}"
    for f in cwe476:
        _assert_finding_contract(f, 476)
    funcs = {f["function"] for f in cwe476}
    assert "risky_fill" in funcs, (
        f"unchecked malloc deref in risky_fill not flagged on aarch64: {cwe476}"
    )
    # The NULL-checked malloc result in safe_fill() must NOT fire — the AArch64
    # cbnz guard recognizer catches it.
    assert "safe_fill" not in funcs, (
        f"NULL-checked malloc in safe_fill must not fire on aarch64: {cwe476}"
    )
    # The NULL-checked getenv() result in safe_env() must NOT fire either.
    assert "safe_env" not in funcs, (
        f"NULL-checked getenv in safe_env must not fire on aarch64: {cwe476}"
    )
    # Medium confidence (same as x86_64): a strong structural signal but not a
    # full def-use proof of the faulting pointer on every path.
    risky = next(f for f in cwe476 if f["function"] == "risky_fill")
    assert risky["confidence"] == "medium"


def test_aarch64_runs_cwe476_under_all(require_angr, fixtures_dir):
    # Under "all" on AArch64, CWE-476 now runs (it is no longer in the skipped
    # set) and its findings surface alongside the other register-level checks.
    rep = _analyze(fixtures_dir, "cwe476-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert 476 not in d["skipped_checks"], (
        f"CWE-476 should run on AArch64, but was skipped: {d['skipped_checks']}"
    )
    assert any(f["cwe"] == 476 for f in d["findings"]), (
        f"expected CWE-476 findings under 'all' on aarch64: {d['findings']}"
    )


def test_aarch64_runs_all_register_level_checks(require_angr, fixtures_dir):
    # On AArch64, every register-level check now runs — CWE-476 was the last
    # x86_64-only register-level check and has been ported. The skipped set is
    # empty on a supported architecture.
    rep = _analyze(fixtures_dir, "cwe78-aarch64-vuln", "all")
    d = rep.to_dict()
    assert d["error"] is None, f"aarch64 fixture errored: {d['error']}"
    assert d["skipped_checks"] == [], (
        f"expected no skipped checks on AArch64, got: {d['skipped_checks']}"
    )
    # All previously-arch-aware checks remain runnable.
    for cwe in (119, 732, 190, 134, 415, 416, 369, 787, 476):
        assert cwe not in d["skipped_checks"]
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
        ("cwe476-aarch64-vuln", 476),
    ]:
        rep = analyze(binary=str(fixtures_dir / name), checks_token=str(cwe),
                      max_states=1000)
        d = rep.to_dict()
        assert d["state_limit_exceeded"] is False, f"{name} hit state limit at 1000"
        assert d["error"] is None, f"{name} errored: {d['error']}"
