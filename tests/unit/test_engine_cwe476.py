"""Fast unit tests for the engine's CWE-476 unchecked-allocator-deref helper.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises
``AngrEngine.unchecked_alloc_dereferences`` without importing angr.

The synthetic instruction streams mirror -O0 x86_64 codegen (Intel syntax, as
capstone renders it):

    unchecked:  call malloc ; mov [rbp-8], rax ; mov rax,[rbp-8] ; mov [rax], 0
                -> result dereferenced with no NULL-check (CANDIDATE)
    checked:    call malloc ; mov [rbp-8], rax ; cmp qword [rbp-8], 0 ; je .ret
                ; mov rax,[rbp-8] ; mov [rax], 0
                -> result NULL-checked before use (NOT a candidate)
"""

from __future__ import annotations

from autopsy.engine import AngrEngine


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding (mirrors test_engine_cwe369.py)
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
    def __init__(self, symbols):
        # addr -> name, lets `call <addr>` resolve to an import name.
        self._symbols = symbols

    def find_symbol(self, addr):
        name = self._symbols.get(addr)
        if name is None:
            return None

        class _Sym:
            pass

        s = _Sym()
        s.name = name
        return s


class _Arch:
    def __init__(self, name="AMD64"):
        self.name = name


class _Project:
    def __init__(self, symbols, arch_name="AMD64"):
        self.arch = _Arch(arch_name)
        self.loader = _Loader(symbols)


def _engine(funcs, symbols, arch_name="AMD64"):
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project(symbols, arch_name)
    eng._cfg = _Cfg(funcs)
    return eng


# Allocator stub addresses the synthetic `call` instructions target.
_MALLOC = 0x500000
_CALLOC = 0x500010
_STRDUP = 0x500020
_GETENV = 0x500030
_FREE = 0x500040
_SYMBOLS = {
    _MALLOC: "malloc",
    _CALLOC: "calloc",
    _STRDUP: "strdup",
    _GETENV: "getenv",
    _FREE: "free",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _unchecked_malloc(base=0x401000, name="alloc_use"):
    """malloc -> spill rax -> reload -> store through it, no NULL-check."""
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "dword ptr [rax], 0"),
        _Insn(base + 0x13, "ret", ""),
    ]
    return _Func(base, name, insns)


def _checked_malloc(base=0x401100, name="safe_alloc"):
    """malloc -> spill -> cmp [slot],0 ; je -> reload -> deref. Guarded."""
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "cmp", "qword ptr [rbp - 8], 0"),
        _Insn(base + 0xE, "je", hex(base + 0x40)),
        _Insn(base + 0x10, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0x14, "mov", "dword ptr [rax], 0"),
        _Insn(base + 0x1A, "ret", ""),
    ]
    return _Func(base, name, insns)


def _checked_via_test(base=0x401200, name="safe_test"):
    """malloc -> spill -> reload -> test reg,reg ; jz -> deref. Guarded."""
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "test", "rax, rax"),
        _Insn(base + 0x10, "je", hex(base + 0x40)),
        _Insn(base + 0x12, "mov", "dword ptr [rax], 0"),
        _Insn(base + 0x18, "ret", ""),
    ]
    return _Func(base, name, insns)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_unchecked_malloc_deref_detected():
    eng = _engine([_unchecked_malloc()], _SYMBOLS)
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    s = sites[0]
    assert s["function"] == "alloc_use"
    assert s["alloc_name"] == "malloc"
    assert s["alloc_address"] == 0x401000
    assert s["address"] == 0x401000 + 0xD
    assert s["slot"] == "rbp-8"


def test_checked_malloc_not_flagged():
    """cmp [slot],0 ; je before the deref is a NULL-check guard -> excluded."""
    eng = _engine([_checked_malloc()], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_checked_via_register_test_not_flagged():
    """`test rax,rax ; jz` on the reloaded result is also a guard -> excluded."""
    eng = _engine([_checked_via_test()], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_result_never_spilled_is_not_tracked():
    """If the allocator result is never stored to a slot, stay conservative."""
    base = 0x401300
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        # rax used directly without ever spilling to a stack slot.
        _Insn(base + 0x5, "add", "rsp, 8"),
        _Insn(base + 0x9, "ret", ""),
    ]
    eng = _engine([_Func(base, "no_spill", insns)], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_result_spilled_but_never_dereferenced():
    """A result stored and read but never used as a pointer base -> no finding."""
    base = 0x401400
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        # Passed to free (rdi <- rax) but not dereferenced.
        _Insn(base + 0xD, "mov", "rdi, rax"),
        _Insn(base + 0x10, "call", hex(_FREE)),
        _Insn(base + 0x15, "ret", ""),
    ]
    eng = _engine([_Func(base, "alloc_free", insns)], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_calloc_strdup_getenv_each_tracked():
    """Every NULL-returning allocator in the set is tracked."""
    for stub, expected in ((_CALLOC, "calloc"), (_STRDUP, "strdup"), (_GETENV, "getenv")):
        base = 0x402000
        insns = [
            _Insn(base + 0x0, "call", hex(stub)),
            _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
            _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
            _Insn(base + 0xD, "movzx", "eax, byte ptr [rax]"),
            _Insn(base + 0x11, "ret", ""),
        ]
        eng = _engine([_Func(base, "use", insns)], _SYMBOLS)
        sites = eng.unchecked_alloc_dereferences()
        assert len(sites) == 1, f"{expected} should be tracked"
        assert sites[0]["alloc_name"] == expected


def test_alias_register_copy_followed():
    """A reg-copy of the reloaded result is followed to the deref."""
    base = 0x402100
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "rcx, rax"),
        _Insn(base + 0x10, "mov", "dword ptr [rcx], 1"),
        _Insn(base + 0x16, "ret", ""),
    ]
    eng = _engine([_Func(base, "via_alias", insns)], _SYMBOLS)
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    assert sites[0]["address"] == base + 0x10


def test_compare_on_other_register_is_not_a_guard():
    """A cmp on an unrelated register does not guard the result -> flagged."""
    base = 0x402200
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "cmp", "edx, 0"),
        _Insn(base + 0xC, "je", hex(base + 0x40)),
        _Insn(base + 0xE, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0x12, "mov", "dword ptr [rax], 0"),
        _Insn(base + 0x18, "ret", ""),
    ]
    eng = _engine([_Func(base, "wrong_guard", insns)], _SYMBOLS)
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    assert sites[0]["function"] == "wrong_guard"


def test_returns_empty_on_unsupported_arch():
    """On an architecture without a CWE-476 walker, the engine returns []."""
    # The synthetic x86_64 fixture's mnemonics/regs are nonsense to the
    # AArch64 walker — but more importantly, an arch that has no walker
    # registered at all (e.g. MIPS) must produce zero findings.
    eng = _engine([_unchecked_malloc()], _SYMBOLS, arch_name="MIPS32")
    assert eng.unchecked_alloc_dereferences() == []


def test_plt_and_simprocedure_skipped():
    plt = _Func(0x403000, "malloc@plt",
                [_Insn(0x403000, "call", hex(_MALLOC))], is_plt=True)
    sim = _Func(0x403100, "sim",
                [_Insn(0x403100, "call", hex(_MALLOC))], is_simprocedure=True)
    eng = _engine([plt, sim], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_non_allocator_call_ignored():
    """A `call free` result is not an allocator and must not be tracked."""
    base = 0x403200
    insns = [
        _Insn(base + 0x0, "call", hex(_FREE)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "dword ptr [rax], 0"),
        _Insn(base + 0x13, "ret", ""),
    ]
    eng = _engine([_Func(base, "not_alloc", insns)], _SYMBOLS)
    assert eng.unchecked_alloc_dereferences() == []


def test_multiple_functions_each_unchecked_reported():
    eng = _engine(
        [_unchecked_malloc(0x404000, "a"), _unchecked_malloc(0x404100, "b")],
        _SYMBOLS,
    )
    sites = eng.unchecked_alloc_dereferences()
    assert {s["function"] for s in sites} == {"a", "b"}


# ---------------------------------------------------------------------------
# AArch64 (AAPCS64) walker
# ---------------------------------------------------------------------------
#
# The AArch64 synthetic instruction streams mirror -O0 clang codegen for an
# `aarch64-linux-gnu` target (capstone AArch64 syntax):
#
#     unchecked:   bl <malloc> ; str x0, [sp] ; ldr x9, [sp]
#                  ; str w8, [x9]            -> unchecked deref (CANDIDATE)
#     cbz-guard:   bl <malloc> ; str x0, [sp] ; ldr x8, [sp]
#                  ; cbnz x8, .L ; ...      -> NULL-check guard (NOT a candidate)
#     cmp-guard:   bl <malloc> ; str x0, [sp] ; ldr x8, [sp]
#                  ; cmp x8, #0 ; b.eq .L   -> NULL-check guard (NOT a candidate)


def _aarch64_unchecked_malloc(base=0x501000, name="alloc_use"):
    """bl malloc -> spill x0 -> reload -> store through it, no NULL-check."""
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x9, [sp]"),
        _Insn(base + 0xC, "str", "w8, [x9]"),
        _Insn(base + 0x10, "ret", ""),
    ]
    return _Func(base, name, insns)


def _aarch64_cbz_guard(base=0x501100, name="safe_cbz"):
    """bl malloc -> spill -> reload -> cbz on alias -> deref. Guarded."""
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x8, [sp]"),
        _Insn(base + 0xC, "cbz", f"x8, {hex(base + 0x40)}"),
        _Insn(base + 0x10, "ldr", "x9, [sp]"),
        _Insn(base + 0x14, "str", "w8, [x9]"),
        _Insn(base + 0x18, "ret", ""),
    ]
    return _Func(base, name, insns)


def _aarch64_cmp_beq_guard(base=0x501200, name="safe_cmp"):
    """bl malloc -> spill -> reload -> cmp x8,#0 ; b.eq -> deref. Guarded."""
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x8, [sp]"),
        _Insn(base + 0xC, "cmp", "x8, #0"),
        _Insn(base + 0x10, "b.eq", hex(base + 0x40)),
        _Insn(base + 0x14, "ldr", "x9, [sp]"),
        _Insn(base + 0x18, "str", "w8, [x9]"),
        _Insn(base + 0x1C, "ret", ""),
    ]
    return _Func(base, name, insns)


def test_aarch64_unchecked_malloc_deref_detected():
    eng = _engine([_aarch64_unchecked_malloc()], _SYMBOLS, arch_name="AARCH64")
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    s = sites[0]
    assert s["function"] == "alloc_use"
    assert s["alloc_name"] == "malloc"
    assert s["alloc_address"] == 0x501000
    assert s["address"] == 0x501000 + 0xC
    # `str x0, [sp]` (no offset) is normalized to slot key "sp+0".
    assert s["slot"] == "sp+0"


def test_aarch64_cbz_guard_not_flagged():
    """cbz on an aliasing register is a direct NULL-check guard."""
    eng = _engine([_aarch64_cbz_guard()], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_cbnz_guard_not_flagged():
    """cbnz on an aliasing register is also a direct NULL-check guard."""
    base = 0x501300
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x8, [sp]"),
        _Insn(base + 0xC, "cbnz", f"x8, {hex(base + 0x18)}"),
        _Insn(base + 0x10, "mov", "w0, #0xffffffff"),
        _Insn(base + 0x14, "ret", ""),
        _Insn(base + 0x18, "ldr", "x9, [sp]"),
        _Insn(base + 0x1C, "str", "w8, [x9]"),
        _Insn(base + 0x20, "ret", ""),
    ]
    eng = _engine([_Func(base, "safe_cbnz", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_cmp_beq_guard_not_flagged():
    eng = _engine([_aarch64_cmp_beq_guard()], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_cmp_xzr_guard_not_flagged():
    """cmp xR, xzr followed by b.eq is the zero-register form of the NULL check."""
    base = 0x501400
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x8, [sp]"),
        _Insn(base + 0xC, "cmp", "x8, xzr"),
        _Insn(base + 0x10, "b.eq", hex(base + 0x40)),
        _Insn(base + 0x14, "ldr", "x9, [sp]"),
        _Insn(base + 0x18, "str", "w8, [x9]"),
        _Insn(base + 0x1C, "ret", ""),
    ]
    eng = _engine([_Func(base, "safe_xzr", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_tst_branch_guard_not_flagged():
    """tst xR, xR followed by b.eq is also a NULL-check guard form."""
    base = 0x501500
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x8, [sp]"),
        _Insn(base + 0xC, "tst", "x8, x8"),
        _Insn(base + 0x10, "b.eq", hex(base + 0x40)),
        _Insn(base + 0x14, "ldr", "x9, [sp]"),
        _Insn(base + 0x18, "str", "w8, [x9]"),
        _Insn(base + 0x1C, "ret", ""),
    ]
    eng = _engine([_Func(base, "safe_tst", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_x29_slot_tracked():
    """str x0, [x29, #-8] / ldr xR, [x29, #-8] tracks an x29-anchored slot too."""
    base = 0x501600
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [x29, #-8]"),
        _Insn(base + 0x8, "ldr", "x9, [x29, #-8]"),
        _Insn(base + 0xC, "str", "w8, [x9]"),
        _Insn(base + 0x10, "ret", ""),
    ]
    eng = _engine([_Func(base, "x29_slot", insns)], _SYMBOLS, arch_name="AARCH64")
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    assert sites[0]["slot"] == "x29-8"


def test_aarch64_alias_register_copy_followed():
    """A reg-copy of the reloaded result is followed to the deref."""
    base = 0x501700
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "ldr", "x9, [sp, #0x8]"),
        _Insn(base + 0xC, "mov", "x10, x9"),
        _Insn(base + 0x10, "str", "wzr, [x10]"),
        _Insn(base + 0x14, "ret", ""),
    ]
    eng = _engine([_Func(base, "via_alias", insns)], _SYMBOLS, arch_name="AARCH64")
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    assert sites[0]["address"] == base + 0x10


def test_aarch64_compare_on_other_register_is_not_a_guard():
    """A cmp on an unrelated register does not guard the result -> flagged."""
    base = 0x501800
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "cmp", "x2, #0"),     # unrelated register
        _Insn(base + 0xC, "b.eq", hex(base + 0x40)),
        _Insn(base + 0x10, "ldr", "x9, [sp]"),
        _Insn(base + 0x14, "str", "w8, [x9]"),
        _Insn(base + 0x18, "ret", ""),
    ]
    eng = _engine([_Func(base, "wrong_guard", insns)], _SYMBOLS, arch_name="AARCH64")
    sites = eng.unchecked_alloc_dereferences()
    assert len(sites) == 1
    assert sites[0]["function"] == "wrong_guard"


def test_aarch64_result_never_spilled_not_tracked():
    """If x0 is never stored to a slot, stay conservative — no finding."""
    base = 0x501900
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        # x0 used directly without ever spilling to a stack slot.
        _Insn(base + 0x4, "add", "sp, sp, #16"),
        _Insn(base + 0x8, "ret", ""),
    ]
    eng = _engine([_Func(base, "no_spill", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_calloc_strdup_getenv_each_tracked():
    """Every NULL-returning allocator in the set is tracked on AArch64."""
    for stub, expected in ((_CALLOC, "calloc"), (_STRDUP, "strdup"), (_GETENV, "getenv")):
        base = 0x502000
        insns = [
            _Insn(base + 0x0, "bl", hex(stub)),
            _Insn(base + 0x4, "str", "x0, [sp]"),
            _Insn(base + 0x8, "ldr", "x9, [sp]"),
            _Insn(base + 0xC, "ldrb", "w0, [x9]"),
            _Insn(base + 0x10, "ret", ""),
        ]
        eng = _engine([_Func(base, "use", insns)], _SYMBOLS, arch_name="AARCH64")
        sites = eng.unchecked_alloc_dereferences()
        assert len(sites) == 1, f"{expected} should be tracked"
        assert sites[0]["alloc_name"] == expected


def test_aarch64_frame_base_deref_is_not_a_finding():
    """A memory access through sp/x29/fp is a spill/reload, not a heap deref."""
    base = 0x502100
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        # A frame-anchored access does not dereference the heap pointer.
        _Insn(base + 0x8, "str", "wzr, [x29, #-4]"),
        _Insn(base + 0xC, "ret", ""),
    ]
    eng = _engine([_Func(base, "frame_only", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_non_allocator_call_ignored():
    """A `bl free` result is not an allocator and must not be tracked."""
    base = 0x502200
    insns = [
        _Insn(base + 0x0, "bl", hex(_FREE)),
        _Insn(base + 0x4, "str", "x0, [sp]"),
        _Insn(base + 0x8, "ldr", "x9, [sp]"),
        _Insn(base + 0xC, "str", "wzr, [x9]"),
        _Insn(base + 0x10, "ret", ""),
    ]
    eng = _engine([_Func(base, "not_alloc", insns)], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_plt_and_simprocedure_skipped():
    plt = _Func(0x503000, "malloc@plt",
                [_Insn(0x503000, "bl", hex(_MALLOC))], is_plt=True)
    sim = _Func(0x503100, "sim",
                [_Insn(0x503100, "bl", hex(_MALLOC))], is_simprocedure=True)
    eng = _engine([plt, sim], _SYMBOLS, arch_name="AARCH64")
    assert eng.unchecked_alloc_dereferences() == []


def test_aarch64_multiple_functions_each_unchecked_reported():
    eng = _engine(
        [_aarch64_unchecked_malloc(0x504000, "a"),
         _aarch64_unchecked_malloc(0x504100, "b")],
        _SYMBOLS,
        arch_name="AARCH64",
    )
    sites = eng.unchecked_alloc_dereferences()
    assert {s["function"] for s in sites} == {"a", "b"}
