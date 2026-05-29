"""Fast unit tests for the engine's CWE-190 size-arithmetic helper.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises ``AngrEngine.size_arith_before_call``
without importing angr.

The synthetic streams mirror -O0 codegen as capstone renders it: x86_64 Intel
syntax (``shl eax, 0xc`` / ``imul eax, ecx``) and AArch64 (``lsl w8, w8, #0xc``
/ ``mul w8, w8, w9``). The size-computing arithmetic always lands in a 32-bit
register view (the truncation/overflow surface) just before the allocator call.
"""

from __future__ import annotations

from autopsy.engine import AngrEngine, CallSite


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding (mirrors test_engine_cwe732.py)
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
        self._by_name = {f.name: f for f in funcs}

    def values(self):
        return list(self._funcs)

    def get(self, name):
        return self._by_name.get(name)

    def floor_func(self, addr):  # pragma: no cover - defensive fallback only
        return None


class _KB:
    def __init__(self, funcs):
        self.functions = _Functions(funcs)


class _Cfg:
    def __init__(self, funcs):
        self.kb = _KB(funcs)


class _Arch:
    def __init__(self, name):
        self.name = name


class _Project:
    def __init__(self, arch_name):
        self.arch = _Arch(arch_name)


def _engine(funcs, arch_name="AMD64"):
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project(arch_name)
    eng._cfg = _Cfg(funcs)
    return eng


def _call(func_name, call_addr):
    return CallSite(
        caller_function=func_name,
        call_address=call_addr,
        target_name="malloc",
        block_addr=0,
    )


# ---------------------------------------------------------------------------
# x86_64 (the original behavior, now routed through the engine helper)
# ---------------------------------------------------------------------------


def test_x86_shift_by_immediate_is_medium():
    # `shl eax, 0xc` — one register source plus an immediate -> medium (False).
    base = 0x401100
    call_addr = base + 0x10
    insns = [
        _Insn(base + 0x0, "mov", "eax, dword ptr [rbp - 0x14]"),
        _Insn(base + 0x4, "shl", "eax, 0xc"),
        _Insn(base + 0x8, "mov", "rdi, rax"),
        _Insn(call_addr, "call", "0x401060"),
    ]
    eng = _engine([_Func(base, "alloc_records", insns)])
    res = eng.size_arith_before_call(_call("alloc_records", call_addr))
    assert res is not None
    addr, mnemonic, two_reg = res
    assert (addr, mnemonic, two_reg) == (base + 0x4, "shl", False)


def test_x86_imul_two_registers_is_high():
    # `imul eax, ecx` — two distinct register sources -> high (True).
    base = 0x401200
    call_addr = base + 0xC
    insns = [
        _Insn(base + 0x0, "mov", "eax, dword ptr [rbp - 8]"),
        _Insn(base + 0x4, "mov", "ecx, dword ptr [rbp - 0xc]"),
        _Insn(base + 0x8, "imul", "eax, ecx"),
        _Insn(call_addr, "call", "0x401060"),
    ]
    eng = _engine([_Func(base, "compute", insns)])
    res = eng.size_arith_before_call(_call("compute", call_addr))
    assert res == (base + 0x8, "imul", True)


def test_x86_no_arith_before_call_returns_none():
    base = 0x401300
    call_addr = base + 0x4
    insns = [
        _Insn(base + 0x0, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(call_addr, "call", "0x401060"),
    ]
    eng = _engine([_Func(base, "passthrough", insns)])
    assert eng.size_arith_before_call(_call("passthrough", call_addr)) is None


def test_x86_arith_after_call_is_ignored():
    # Arithmetic AFTER the call address must not be attributed to the size.
    base = 0x401400
    call_addr = base + 0x4
    insns = [
        _Insn(base + 0x0, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(call_addr, "call", "0x401060"),
        _Insn(base + 0x8, "imul", "eax, ecx"),  # after the call
    ]
    eng = _engine([_Func(base, "later", insns)])
    assert eng.size_arith_before_call(_call("later", call_addr)) is None


def test_x86_takes_last_arith_before_call():
    # Two arithmetic ops precede the call; the last one wins.
    base = 0x401500
    call_addr = base + 0x10
    insns = [
        _Insn(base + 0x0, "add", "eax, ebx"),    # earlier (two-reg)
        _Insn(base + 0x8, "shl", "eax, 0x2"),    # later (one-reg) -> chosen
        _Insn(call_addr, "call", "0x401060"),
    ]
    eng = _engine([_Func(base, "twoops", insns)])
    res = eng.size_arith_before_call(_call("twoops", call_addr))
    assert res == (base + 0x8, "shl", False)


# ---------------------------------------------------------------------------
# AArch64 (the new arch-aware path)
# ---------------------------------------------------------------------------


def test_aarch64_lsl_by_immediate_is_medium():
    # `lsl w8, w8, #0xc` — `count * 4096`: destination == single source, plus an
    # immediate shift amount -> one logical register source -> medium (False).
    base = 0x401100
    call_addr = base + 0x10
    insns = [
        _Insn(base + 0x0, "ldur", "w8, [x29, #-4]"),
        _Insn(base + 0x4, "lsl", "w8, w8, #0xc"),
        _Insn(base + 0x8, "ldrsw", "x0, [sp, #8]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "alloc_records", insns)], arch_name="AARCH64")
    res = eng.size_arith_before_call(_call("alloc_records", call_addr))
    assert res == (base + 0x4, "lsl", False)


def test_aarch64_mul_two_registers_is_high():
    # `mul w8, w8, w9` — `count * width`: two distinct register sources (w8, w9)
    # after the destination -> high (True).
    base = 0x401200
    call_addr = base + 0x14
    insns = [
        _Insn(base + 0x0, "ldur", "w8, [x29, #-4]"),
        _Insn(base + 0x4, "ldr", "w9, [sp, #8]"),
        _Insn(base + 0x8, "mul", "w8, w8, w9"),
        _Insn(base + 0xC, "ldrsw", "x0, [sp, #4]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "alloc2", insns)], arch_name="AARCH64")
    res = eng.size_arith_before_call(_call("alloc2", call_addr))
    assert res == (base + 0x8, "mul", True)


def test_aarch64_madd_three_registers_is_high():
    # `madd w8, w9, w10, w11` — multiply-add with three register sources -> high.
    base = 0x401300
    call_addr = base + 0x8
    insns = [
        _Insn(base + 0x0, "madd", "w8, w9, w10, w11"),
        _Insn(base + 0x4, "ldrsw", "x0, [sp, #4]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "fma", insns)], arch_name="AARCH64")
    res = eng.size_arith_before_call(_call("fma", call_addr))
    assert res == (base + 0x0, "madd", True)


def test_aarch64_add_immediate_is_medium():
    # `add w8, w8, #1` — register destination/source plus an immediate -> medium.
    base = 0x401400
    call_addr = base + 0x8
    insns = [
        _Insn(base + 0x0, "add", "w8, w8, #1"),
        _Insn(base + 0x4, "ldrsw", "x0, [sp, #4]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "incr", insns)], arch_name="AARCH64")
    res = eng.size_arith_before_call(_call("incr", call_addr))
    assert res == (base + 0x0, "add", False)


def test_aarch64_x86_mnemonics_not_matched():
    # An x86 `shl`/`imul` token must NOT match on AArch64 (different mnemonic
    # set), and x86 e** registers are not AArch64 size registers.
    base = 0x401500
    call_addr = base + 0x8
    insns = [
        _Insn(base + 0x0, "imul", "eax, ecx"),   # x86 form, irrelevant on arm
        _Insn(base + 0x4, "ldrsw", "x0, [sp, #4]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "wrongarch", insns)], arch_name="AARCH64")
    assert eng.size_arith_before_call(_call("wrongarch", call_addr)) is None


def test_aarch64_no_arith_returns_none():
    base = 0x401600
    call_addr = base + 0x4
    insns = [
        _Insn(base + 0x0, "ldr", "x0, [sp, #8]"),
        _Insn(call_addr, "bl", "#0x401060"),
    ]
    eng = _engine([_Func(base, "plain", insns)], arch_name="AARCH64")
    assert eng.size_arith_before_call(_call("plain", call_addr)) is None


def test_unsupported_arch_returns_none():
    base = 0x401700
    call_addr = base + 0x4
    insns = [
        _Insn(base + 0x0, "mul", "r3, r4, r5"),
        _Insn(call_addr, "bl", "0x401060"),
    ]
    eng = _engine([_Func(base, "mips", insns)], arch_name="MIPS32")
    assert eng.size_arith_before_call(_call("mips", call_addr)) is None
