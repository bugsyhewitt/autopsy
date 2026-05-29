"""Fast unit tests for the engine's CWE-369 division-site helper.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises
``AngrEngine.divisions_with_unguarded_divisor`` without importing angr.

The synthetic instruction streams mirror -O0 x86_64 codegen (Intel syntax, as
capstone renders it):

    unguarded:   mov eax,[rbp-4] ; cdq ; idiv dword ptr [rbp-8]
                 -> no zero-check on the divisor (CANDIDATE)
    guarded:     cmp dword ptr [rbp-8], 0 ; je .ret ; ... ; idiv ...
                 -> divisor checked before the divide (NOT a candidate)
"""

from __future__ import annotations

from autopsy.engine import AngrEngine


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding (mirrors test_engine_cwe134.py)
# ---------------------------------------------------------------------------


class _Insn:
    def __init__(self, address, mnemonic, op_str):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str


class _Capstone:
    def __init__(self, insns):
        self.insns = insns


class _Block:
    def __init__(self, addr, insns):
        self.addr = addr
        self.capstone = _Capstone(insns)


class _Func:
    def __init__(self, addr, name, insns, is_plt=False, is_simprocedure=False):
        self.addr = addr
        self.name = name
        self.is_plt = is_plt
        self.is_simprocedure = is_simprocedure
        self.blocks = [_Block(addr, insns)]


class _Functions:
    def __init__(self, funcs):
        self._funcs = funcs
        self._by_addr = {f.addr: f for f in funcs}

    def values(self):
        return list(self._funcs)

    def get(self, addr):
        return self._by_addr.get(addr)


class _KB:
    def __init__(self, funcs):
        self.functions = _Functions(funcs)


class _Cfg:
    def __init__(self, funcs):
        self.kb = _KB(funcs)


class _Loader:
    def find_symbol(self, addr):
        return None


class _Arch:
    def __init__(self, name="AMD64"):
        self.name = name


class _Project:
    def __init__(self, arch_name="AMD64"):
        self.arch = _Arch(arch_name)
        self.loader = _Loader()


def _engine(funcs, arch_name="AMD64"):
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project(arch_name)
    eng._cfg = _Cfg(funcs)
    return eng


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _unguarded_reg_div(base=0x401200, name="compute"):
    """idiv with a register divisor and no preceding zero-check."""
    insns = [
        _Insn(base + 0x0, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0x4, "mov", "ecx, dword ptr [rbp - 8]"),
        _Insn(base + 0x8, "cdq", ""),
        _Insn(base + 0xA, "idiv", "ecx"),
    ]
    return _Func(base, name, insns)


def _guarded_div(base=0x401300, name="safe_div"):
    """idiv preceded by `cmp ecx, 0 ; je ...` — a zero-check guard."""
    insns = [
        _Insn(base + 0x0, "mov", "ecx, dword ptr [rbp - 8]"),
        _Insn(base + 0x4, "cmp", "ecx, 0"),
        _Insn(base + 0x7, "je", hex(base + 0x20)),
        _Insn(base + 0x9, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0xD, "cdq", ""),
        _Insn(base + 0xF, "idiv", "ecx"),
    ]
    return _Func(base, name, insns)


def _unguarded_mem_div(base=0x401400, name="mem_div"):
    """idiv with a memory-operand divisor and no zero-check."""
    insns = [
        _Insn(base + 0x0, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0x4, "cdq", ""),
        _Insn(base + 0x6, "idiv", "dword ptr [rbp - 8]"),
    ]
    return _Func(base, name, insns)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_unguarded_register_division_detected():
    eng = _engine([_unguarded_reg_div()])
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    d = divs[0]
    assert d["function"] == "compute"
    assert d["divisor"] == "ecx"
    assert d["address"] == 0x401200 + 0xA


def test_guarded_division_not_flagged():
    """A divisor checked with cmp/je before the divide is guarded -> excluded."""
    eng = _engine([_guarded_div()])
    assert eng.divisions_with_unguarded_divisor() == []


def test_memory_operand_divisor_detected():
    eng = _engine([_unguarded_mem_div()])
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    assert divs[0]["divisor"] == "dword ptr [rbp - 8]"


def test_test_instruction_also_counts_as_guard():
    """`test ecx, ecx ; jz` is the common zero-check idiom -> guarded."""
    base = 0x401500
    insns = [
        _Insn(base + 0x0, "mov", "ecx, dword ptr [rbp - 8]"),
        _Insn(base + 0x4, "test", "ecx, ecx"),
        _Insn(base + 0x6, "jz", hex(base + 0x20)),
        _Insn(base + 0x8, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0xC, "cdq", ""),
        _Insn(base + 0xE, "idiv", "ecx"),
    ]
    eng = _engine([_Func(base, "tested", insns)])
    assert eng.divisions_with_unguarded_divisor() == []


def test_compare_on_other_register_is_not_a_guard():
    """A cmp on an unrelated register does not guard the divisor -> flagged."""
    base = 0x401600
    insns = [
        _Insn(base + 0x0, "mov", "ecx, dword ptr [rbp - 8]"),
        _Insn(base + 0x4, "cmp", "edx, 0"),
        _Insn(base + 0x7, "je", hex(base + 0x20)),
        _Insn(base + 0x9, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0xD, "cdq", ""),
        _Insn(base + 0xF, "idiv", "ecx"),
    ]
    eng = _engine([_Func(base, "wrong_guard", insns)])
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    assert divs[0]["function"] == "wrong_guard"


def test_no_division_returns_empty():
    base = 0x401700
    insns = [
        _Insn(base + 0x0, "mov", "eax, dword ptr [rbp - 4]"),
        _Insn(base + 0x4, "add", "eax, 1"),
        _Insn(base + 0x7, "ret", ""),
    ]
    eng = _engine([_Func(base, "noop", insns)])
    assert eng.divisions_with_unguarded_divisor() == []


def test_returns_empty_on_unsupported_arch():
    """The helper is arch-aware for AMD64/AARCH64 only; [] on anything else."""
    eng = _engine([_unguarded_reg_div()], arch_name="MIPS32")
    assert eng.divisions_with_unguarded_divisor() == []


# ---------------------------------------------------------------------------
# AArch64 fixtures and tests
#
# AArch64 integer division uses `sdiv`/`udiv` with the form
# `sdiv Wd, Wn, Wm` — the *third* operand (Wm/Xm) is the divisor (unlike x86_64
# where the single explicit operand is the divisor). The guard idioms that mark
# a divisor as zero-checked are `cbz`/`cbnz <reg>` (compare-and-branch on zero)
# and `cmp <reg>, #0` followed by a conditional branch (`b.eq`/`b.ne`/...).
# ---------------------------------------------------------------------------


def _aarch64_unguarded_div(base=0x410200, name="compute", mnemonic="sdiv"):
    """sdiv with a register divisor and no preceding zero-check."""
    insns = [
        _Insn(base + 0x0, "ldr", "w8, [sp, #0xc]"),
        _Insn(base + 0x4, "ldr", "w9, [sp, #0x8]"),
        _Insn(base + 0x8, mnemonic, "w0, w8, w9"),
    ]
    return _Func(base, name, insns)


def _aarch64_cbz_guarded_div(base=0x410300, name="safe_div"):
    """sdiv preceded by `cbz w9, .ret` — a compare-and-branch zero-check."""
    insns = [
        _Insn(base + 0x0, "ldr", "w9, [sp, #0x8]"),
        _Insn(base + 0x4, "cbz", "w9, #" + hex(base + 0x20)),
        _Insn(base + 0x8, "ldr", "w8, [sp, #0xc]"),
        _Insn(base + 0xC, "sdiv", "w0, w8, w9"),
    ]
    return _Func(base, name, insns)


def _aarch64_cmp_guarded_div(base=0x410400, name="cmp_safe"):
    """sdiv preceded by `cmp w9, #0 ; b.eq .ret` — the cmp+branch zero-check."""
    insns = [
        _Insn(base + 0x0, "ldr", "w9, [sp, #0x8]"),
        _Insn(base + 0x4, "cmp", "w9, #0"),
        _Insn(base + 0x8, "b.eq", "#" + hex(base + 0x20)),
        _Insn(base + 0xC, "ldr", "w8, [sp, #0xc]"),
        _Insn(base + 0x10, "sdiv", "w0, w8, w9"),
    ]
    return _Func(base, name, insns)


def test_aarch64_unguarded_signed_division_detected():
    eng = _engine([_aarch64_unguarded_div()], arch_name="AARCH64")
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    d = divs[0]
    assert d["function"] == "compute"
    # The divisor is the third operand on AArch64.
    assert d["divisor"] == "w9"
    assert d["address"] == 0x410200 + 0x8


def test_aarch64_unguarded_unsigned_division_detected():
    eng = _engine([_aarch64_unguarded_div(mnemonic="udiv")], arch_name="AARCH64")
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    assert divs[0]["divisor"] == "w9"


def test_aarch64_cbz_guarded_division_not_flagged():
    """`cbz w9, .ret` directly tests the divisor against zero -> guarded."""
    eng = _engine([_aarch64_cbz_guarded_div()], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_cmp_guarded_division_not_flagged():
    """`cmp w9, #0 ; b.eq` is the cmp+branch zero-check idiom -> guarded."""
    eng = _engine([_aarch64_cmp_guarded_div()], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_x_register_divisor_widening_matched_in_guard():
    """A `cbz x9` guard covers a `sdiv ..., x9` divisor (same logical reg)."""
    base = 0x410500
    insns = [
        _Insn(base + 0x0, "ldr", "x9, [sp, #0x8]"),
        _Insn(base + 0x4, "cbz", "x9, #" + hex(base + 0x20)),
        _Insn(base + 0x8, "ldr", "x8, [sp, #0x10]"),
        _Insn(base + 0xC, "sdiv", "x0, x8, x9"),
    ]
    eng = _engine([_Func(base, "x_guard", insns)], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_cbz_on_other_register_is_not_a_guard():
    """`cbz` on an unrelated register does not guard the divisor -> flagged."""
    base = 0x410600
    insns = [
        _Insn(base + 0x0, "ldr", "w9, [sp, #0x8]"),
        _Insn(base + 0x4, "cbz", "w7, #" + hex(base + 0x20)),
        _Insn(base + 0x8, "ldr", "w8, [sp, #0xc]"),
        _Insn(base + 0xC, "sdiv", "w0, w8, w9"),
    ]
    eng = _engine([_Func(base, "wrong_guard", insns)], arch_name="AARCH64")
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    assert divs[0]["function"] == "wrong_guard"


def test_aarch64_slot_aliased_guard_not_flagged():
    """Real -O0 codegen: the guard tests a register reloaded from the same slot
    as the divisor. `cbnz w8, ...` where both w8 and the divisor w9 come from
    `[sp,#0x4]` is the zero-check on that slot -> guarded (no false positive)."""
    base = 0x410A00
    insns = [
        _Insn(base + 0x0, "str", "w1, [sp, #0x4]"),
        _Insn(base + 0x4, "ldr", "w8, [sp, #0x4]"),     # guard reg <- slot
        _Insn(base + 0x8, "cbnz", "w8, #" + hex(base + 0x20)),
        _Insn(base + 0xC, "ldr", "w8b, [sp, #0x8]"),    # numerator
        _Insn(base + 0x10, "ldr", "w9, [sp, #0x4]"),    # divisor <- same slot
        _Insn(base + 0x14, "sdiv", "w8, w8, w9"),
    ]
    eng = _engine([_Func(base, "safe_ratio", insns)], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_cmp_slot_aliased_guard_not_flagged():
    """`cmp w8, #0 ; b.eq` where w8 reloads the divisor's slot -> guarded."""
    base = 0x410B00
    insns = [
        _Insn(base + 0x0, "str", "w1, [sp, #0x4]"),
        _Insn(base + 0x4, "ldr", "w8, [sp, #0x4]"),
        _Insn(base + 0x8, "cmp", "w8, #0"),
        _Insn(base + 0xC, "b.eq", "#" + hex(base + 0x20)),
        _Insn(base + 0x10, "ldr", "w9, [sp, #0x4]"),
        _Insn(base + 0x14, "sdiv", "w8, w8, w9"),
    ]
    eng = _engine([_Func(base, "cmp_slot_safe", insns)], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_guard_on_unrelated_slot_is_not_a_guard():
    """A cbz on a register loaded from a DIFFERENT slot does not guard the
    divisor -> flagged."""
    base = 0x410C00
    insns = [
        _Insn(base + 0x0, "ldr", "w8, [sp, #0x10]"),     # unrelated slot
        _Insn(base + 0x4, "cbz", "w8, #" + hex(base + 0x20)),
        _Insn(base + 0x8, "ldr", "w9, [sp, #0x4]"),      # divisor slot
        _Insn(base + 0xC, "sdiv", "w0, w8, w9"),
    ]
    eng = _engine([_Func(base, "wrong_slot", insns)], arch_name="AARCH64")
    divs = eng.divisions_with_unguarded_divisor()
    assert len(divs) == 1
    assert divs[0]["function"] == "wrong_slot"


def test_aarch64_no_division_returns_empty():
    base = 0x410700
    insns = [
        _Insn(base + 0x0, "ldr", "w8, [sp, #0xc]"),
        _Insn(base + 0x4, "add", "w8, w8, #1"),
        _Insn(base + 0x8, "ret", ""),
    ]
    eng = _engine([_Func(base, "noop", insns)], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_aarch64_plt_and_simprocedure_skipped():
    plt = _Func(
        0x410800, "div@plt", [_Insn(0x410800, "sdiv", "w0, w8, w9")], is_plt=True
    )
    sim = _Func(
        0x410900, "sim", [_Insn(0x410900, "sdiv", "w0, w8, w9")], is_simprocedure=True
    )
    eng = _engine([plt, sim], arch_name="AARCH64")
    assert eng.divisions_with_unguarded_divisor() == []


def test_plt_and_simprocedure_skipped():
    """Library stubs must not be scanned for divisions."""
    plt = _Func(0x401800, "div@plt", [_Insn(0x401800, "idiv", "ecx")], is_plt=True)
    sim = _Func(0x401900, "sim", [_Insn(0x401900, "idiv", "ecx")], is_simprocedure=True)
    eng = _engine([plt, sim])
    assert eng.divisions_with_unguarded_divisor() == []


def test_multiple_functions_each_division_reported():
    eng = _engine([_unguarded_reg_div(0x402000, "a"), _unguarded_mem_div(0x402100, "b")])
    divs = eng.divisions_with_unguarded_divisor()
    assert {d["function"] for d in divs} == {"a", "b"}
