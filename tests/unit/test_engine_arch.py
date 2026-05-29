"""Fast unit tests for the engine's architecture-support logic.

These exercise the arch guard, the per-architecture check partitioning, and the
architecture-dependent direct-call mnemonic selection WITHOUT importing angr.
``AngrEngine`` is instantiated via ``__new__`` (bypassing the angr-loading
``__init__``) and given a tiny fake ``project`` carrying only ``arch.name``.
"""

import pytest

from autopsy.engine import AngrEngine, EngineError


class _FakeArch:
    def __init__(self, name):
        self.name = name


class _FakeProject:
    def __init__(self, arch_name):
        self.arch = _FakeArch(arch_name)


def _engine_for_arch(arch_name):
    """Build an AngrEngine with a fake project on ``arch_name``, no angr."""
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _FakeProject(arch_name)
    return eng


# -- assert_supported -----------------------------------------------------


def test_amd64_is_supported():
    _engine_for_arch("AMD64").assert_supported()  # must not raise


def test_aarch64_is_supported():
    _engine_for_arch("AARCH64").assert_supported()  # must not raise


def test_unsupported_arch_rejected():
    with pytest.raises(EngineError) as exc:
        _engine_for_arch("MIPS32").assert_supported()
    msg = str(exc.value)
    assert "MIPS32" in msg
    assert "AMD64" in msg and "AARCH64" in msg


# -- checks_supported_on_arch --------------------------------------------


def test_amd64_runs_every_check():
    eng = _engine_for_arch("AMD64")
    runnable, skipped = eng.checks_supported_on_arch([119, 190, 415, 416, 78, 787])
    assert runnable == [119, 190, 415, 416, 78, 787]
    assert skipped == []


def test_aarch64_runs_only_arch_agnostic_checks():
    eng = _engine_for_arch("AARCH64")
    runnable, skipped = eng.checks_supported_on_arch([119, 190, 415, 416, 78, 787, 476])
    # The arch-agnostic + arch-aware checks run on AArch64. CWE-119 is now
    # arch-aware (its scaled-index buffer-access scanner knows the AArch64
    # ldrsw/sxtw + add base+index + deref forms), as are CWE-415, CWE-416, and
    # CWE-787 (the malloc+bulk-copy co-location heuristic; the length-arg
    # immediate resolver knows the AAPCS64 `x2`/`w2` form).
    assert runnable == [119, 190, 415, 416, 78, 787]
    # The remaining x86_64-only register-level check (CWE-476 NULL-deref) is
    # still skipped.
    assert skipped == [476]


def test_aarch64_runs_cwe732_permission_check():
    # CWE-732 is the arch-aware register-level check: it reads only an immediate
    # mode/mask out of the AAPCS64 argument register, so it runs on AArch64.
    # CWE-787 is now arch-aware too (length immediate read from x2/w2).
    # CWE-476 (NULL-deref) remains x86_64-only.
    eng = _engine_for_arch("AARCH64")
    runnable, skipped = eng.checks_supported_on_arch([732, 787, 78, 476])
    assert runnable == [732, 787, 78]
    assert skipped == [476]


def test_aarch64_partition_preserves_request_order():
    eng = _engine_for_arch("AARCH64")
    runnable, skipped = eng.checks_supported_on_arch([78, 476, 190, 787])
    assert runnable == [78, 190, 787]
    assert skipped == [476]


def test_aarch64_cwe78_only_is_fully_runnable():
    eng = _engine_for_arch("AARCH64")
    runnable, skipped = eng.checks_supported_on_arch([78])
    assert runnable == [78]
    assert skipped == []


# -- direct-call mnemonic selection --------------------------------------


def test_amd64_uses_call_mnemonic():
    eng = _engine_for_arch("AMD64")
    assert eng._call_mnemonics() == frozenset({"call"})


def test_aarch64_uses_bl_mnemonic():
    eng = _engine_for_arch("AARCH64")
    assert eng._call_mnemonics() == frozenset({"bl"})


def test_unknown_arch_falls_back_to_call():
    eng = _engine_for_arch("PPC64")
    assert eng._call_mnemonics() == frozenset({"call"})


# -- _resolve_call_target operand parsing --------------------------------


class _FakeInsn:
    def __init__(self, op_str):
        self.op_str = op_str


class _FakeFunc:
    def __init__(self, name):
        self.name = name


class _FakeFunctions:
    def __init__(self, mapping):
        self._m = mapping

    def get(self, addr):
        return self._m.get(addr)


class _FakeKB:
    def __init__(self, mapping):
        self.functions = _FakeFunctions(mapping)


class _FakeCfg:
    def __init__(self, mapping):
        self.kb = _FakeKB(mapping)


def _resolve(arch_name, op_str, target_addr, name):
    eng = _engine_for_arch(arch_name)
    cfg = _FakeCfg({target_addr: _FakeFunc(name)})
    return eng._resolve_call_target(_FakeInsn(op_str), cfg)


def test_resolve_x86_64_call_operand():
    # x86_64 `call 0x401199` form.
    assert _resolve("AMD64", "0x401199", 0x401199, "system") == "system"


def test_resolve_aarch64_bl_operand_with_hash():
    # AArch64 `bl #0x210234` form — capstone prefixes the immediate with '#'.
    assert _resolve("AARCH64", "#0x210234", 0x210234, "system") == "system"


def test_resolve_aarch64_strips_plt_decoration():
    assert _resolve("AARCH64", "#0x210218", 0x210218, "fgets@plt") == "fgets"
