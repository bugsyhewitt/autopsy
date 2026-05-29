"""Fast unit tests for the intra-procedural CWE-415 double-free scanner.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises ``autopsy.checks.cwe415._scan_function`` /
``run`` for BOTH architectures without importing angr.

The intra-procedural pass is arch-aware: the slot-tracking abstraction is
shared, while the concrete register names, store/load mnemonics, and stack-slot
operand syntax differ between x86_64 (``rax``/``rdi``; ``mov`` over
``[rbp-N]``/``[rsp-N]``) and AArch64 (``x0``; ``str``/``ldr`` over
``[sp,#N]``/``[x29,#N]``). The synthetic streams below mirror -O0 codegen on
each architecture as capstone renders it.

The single-hop interprocedural companion pass (``cwe415_interproc``) is
x86_64-only; these synthetic functions contain no callee that frees an incoming
parameter, so that pass contributes nothing and the assertions isolate the
intra-procedural scanner.
"""

from __future__ import annotations

from autopsy.checks import cwe415


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
    from autopsy.engine import AngrEngine

    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project(arch_name)
    eng._cfg = _Cfg(funcs)
    return eng


# Resolve malloc/free via named PLT-stub functions at the call targets.
_MALLOC_ADDR = 0x402000
_FREE_ADDR = 0x402100


def _libc_stubs():
    return [
        _Func(_MALLOC_ADDR, "malloc", [_Insn(_MALLOC_ADDR, "jmp", "0x0")], is_plt=True),
        _Func(_FREE_ADDR, "free", [_Insn(_FREE_ADDR, "jmp", "0x0")], is_plt=True),
    ]


# ---------------------------------------------------------------------------
# x86_64 (SysV)
# ---------------------------------------------------------------------------


def _x86_double_free(base=0x401100, name="dbl", second_frees=True):
    """malloc -> store rax to slot -> free(slot) [-> free(slot)]."""
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC_ADDR)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),  # store ptr to slot
        _Insn(base + 0xA, "mov", "rdi, qword ptr [rbp - 8]"),  # reload for free
        _Insn(base + 0xE, "call", hex(_FREE_ADDR)),            # first free
    ]
    if second_frees:
        insns += [
            _Insn(base + 0x13, "mov", "rdi, qword ptr [rbp - 8]"),  # reload again
            _Insn(base + 0x17, "call", hex(_FREE_ADDR)),            # double-free
        ]
    insns.append(_Insn(base + 0x1C, "ret", ""))
    return _Func(base, name, insns)


def test_x86_double_free_flagged():
    caller = _x86_double_free()
    eng = _engine([caller, *_libc_stubs()])
    findings = cwe415.run(eng)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 415
    assert f.function == "dbl"
    assert f.confidence == "high"
    assert f.address == 0x401100 + 0x17  # the SECOND free's address
    assert len(f.taint_trace) == 3


def test_x86_single_free_not_flagged():
    caller = _x86_double_free(second_frees=False)
    eng = _engine([caller, *_libc_stubs()])
    assert cwe415.run(eng) == []


def test_x86_double_free_via_register_copy_alias():
    # malloc -> [rbp-8] -> reload into rax -> `mov rdi, rax` -> free, twice.
    base = 0x401300
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC_ADDR)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0xA, "mov", "rax, qword ptr [rbp - 8]"),  # reload into rax
        _Insn(base + 0xE, "mov", "rdi, rax"),                  # copy into arg reg
        _Insn(base + 0x11, "call", hex(_FREE_ADDR)),
        _Insn(base + 0x16, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0x1A, "mov", "rdi, rax"),
        _Insn(base + 0x1D, "call", hex(_FREE_ADDR)),
        _Insn(base + 0x22, "ret", ""),
    ]
    eng = _engine([_Func(base, "aliased", insns), *_libc_stubs()])
    findings = cwe415.run(eng)
    assert len(findings) == 1 and findings[0].confidence == "high"


# ---------------------------------------------------------------------------
# AArch64 (AAPCS64) — the arch-aware path this change adds
# ---------------------------------------------------------------------------
#
# AArch64 -O0 codegen (as capstone renders it): the allocator result in `x0` is
# spilled with `str x0, [sp, #8]`; before each `bl <free>` it is reloaded with
# `ldr x0, [sp, #8]`. Two such free calls with no intervening call -> double-free.


def _aarch64_double_free(base=0x210158, name="double_free", second_frees=True):
    insns = [
        _Insn(base + 0x0, "mov", "x0, #0x20"),
        _Insn(base + 0x4, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x8, "str", "x0, [sp, #8]"),   # spill ptr to slot
        _Insn(base + 0xC, "ldr", "x0, [sp, #8]"),   # reload for first free
        _Insn(base + 0x10, "bl", hex(_FREE_ADDR)),  # first free
    ]
    if second_frees:
        insns += [
            _Insn(base + 0x14, "ldr", "x0, [sp, #8]"),  # reload again
            _Insn(base + 0x18, "bl", hex(_FREE_ADDR)),  # double-free
        ]
    insns.append(_Insn(base + 0x1C, "ret", ""))
    return _Func(base, name, insns)


def test_aarch64_double_free_flagged():
    caller = _aarch64_double_free()
    eng = _engine([caller, *_libc_stubs()], arch_name="AARCH64")
    findings = cwe415.run(eng)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 415
    assert f.function == "double_free"
    assert f.confidence == "high"
    assert f.address == 0x210158 + 0x18  # the SECOND `bl free`
    assert len(f.taint_trace) == 3


def test_aarch64_single_free_not_flagged():
    caller = _aarch64_double_free(second_frees=False)
    eng = _engine([caller, *_libc_stubs()], arch_name="AARCH64")
    assert cwe415.run(eng) == []


def test_aarch64_double_free_x29_frame_slot():
    # Frame-relative slot `[x29, #-8]` instead of `[sp, #N]`.
    base = 0x210300
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [x29, #-8]"),
        _Insn(base + 0x8, "ldr", "x0, [x29, #-8]"),
        _Insn(base + 0xC, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x10, "ldr", "x0, [x29, #-8]"),
        _Insn(base + 0x14, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x18, "ret", ""),
    ]
    eng = _engine([_Func(base, "framed", insns), *_libc_stubs()], arch_name="AARCH64")
    findings = cwe415.run(eng)
    assert len(findings) == 1 and findings[0].confidence == "high"


def test_aarch64_double_free_via_register_copy_alias():
    # malloc -> slot -> `ldr x9, [sp,#8]` -> `mov x0, x9` -> free, twice.
    base = 0x210400
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [sp, #8]"),
        _Insn(base + 0x8, "ldr", "x9, [sp, #8]"),   # reload into scratch
        _Insn(base + 0xC, "mov", "x0, x9"),         # copy into arg reg
        _Insn(base + 0x10, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x14, "ldr", "x9, [sp, #8]"),
        _Insn(base + 0x18, "mov", "x0, x9"),
        _Insn(base + 0x1C, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x20, "ret", ""),
    ]
    eng = _engine([_Func(base, "aliased", insns), *_libc_stubs()], arch_name="AARCH64")
    findings = cwe415.run(eng)
    assert len(findings) == 1 and findings[0].confidence == "high"


def test_aarch64_free_realloc_resets_not_flagged():
    # malloc -> free -> a NEW malloc overlays the slot -> single later free.
    # The freed-then-reallocated slot is no longer a double-free candidate.
    base = 0x210500
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [sp, #8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #8]"),
        _Insn(base + 0xC, "bl", hex(_FREE_ADDR)),       # first free
        _Insn(base + 0x10, "bl", hex(_MALLOC_ADDR)),    # reallocation
        _Insn(base + 0x14, "str", "x0, [sp, #8]"),
        _Insn(base + 0x18, "ldr", "x0, [sp, #8]"),
        _Insn(base + 0x1C, "bl", hex(_FREE_ADDR)),      # free of the NEW alloc
        _Insn(base + 0x20, "ret", ""),
    ]
    eng = _engine([_Func(base, "realloced", insns), *_libc_stubs()], arch_name="AARCH64")
    assert cwe415.run(eng) == []


def test_returns_empty_on_unsupported_arch():
    caller = _aarch64_double_free()
    eng = _engine([caller, *_libc_stubs()], arch_name="MIPS32")
    assert cwe415.run(eng) == []
