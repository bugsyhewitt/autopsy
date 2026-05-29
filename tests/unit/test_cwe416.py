"""Fast unit tests for the intra-procedural CWE-416 use-after-free scanner.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises ``autopsy.checks.cwe416._scan_function`` /
``run`` for BOTH architectures without importing angr.

The intra-procedural pass is arch-aware: the slot-tracking abstraction is
shared, while the concrete register names, store/load mnemonics, stack-slot
operand syntax, and dereference syntax differ between x86_64 (``rax``/``rdi``;
``mov`` over ``[rbp-N]``/``[rsp-N]``; deref ``[rax]``) and AArch64 (``x0``;
``str``/``ldr`` over ``[sp,#N]``/``[x29,#N]``; deref ``[x9]``). The synthetic
streams below mirror -O0 codegen on each architecture as capstone renders it.

The single-hop interprocedural companion pass (``cwe416_interproc``) is
x86_64-only; these synthetic functions contain no callee that frees an incoming
parameter, so that pass contributes nothing and the assertions isolate the
intra-procedural scanner. (The interproc pass is tested in
``test_cwe416_interproc.py``.)
"""

from __future__ import annotations

from autopsy.checks import cwe416


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding (mirrors test_cwe415.py)
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


def _x86_uaf(base=0x401100, name="uaf", uses=True, via_copy=False):
    """malloc -> slot -> free(slot) [-> reload slot -> deref]."""
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC_ADDR)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),  # store ptr to slot
        _Insn(base + 0xA, "mov", "rdi, qword ptr [rbp - 8]"),  # reload for free
        _Insn(base + 0xE, "call", hex(_FREE_ADDR)),            # free
    ]
    if uses:
        if via_copy:
            insns += [
                _Insn(base + 0x13, "mov", "rax, qword ptr [rbp - 8]"),  # reload
                _Insn(base + 0x17, "mov", "rcx, rax"),                  # copy alias
                _Insn(base + 0x1A, "mov", "byte ptr [rcx], 0x58"),      # deref USE
            ]
        else:
            insns += [
                _Insn(base + 0x13, "mov", "rax, qword ptr [rbp - 8]"),  # reload
                _Insn(base + 0x17, "mov", "byte ptr [rax], 0x58"),      # deref USE
            ]
    insns.append(_Insn(base + 0x20, "ret", ""))
    return _Func(base, name, insns)


def test_x86_use_after_free_flagged():
    eng = _engine([_x86_uaf(), *_libc_stubs()])
    findings = cwe416.run(eng)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 416
    assert f.function == "uaf"
    # Direct slot reload before the deref -> confirmed aliasing -> high.
    assert f.confidence == "high"
    assert f.address == 0x401100 + 0x17  # the deref address
    assert len(f.taint_trace) == 3


def test_x86_free_without_use_not_flagged():
    eng = _engine([_x86_uaf(uses=False), *_libc_stubs()])
    assert cwe416.run(eng) == []


def test_x86_use_via_register_copy_still_high():
    # The slot is reloaded into rax (confirmed alias) and then copied into rcx;
    # the copy inherits the confirmed-reload provenance, so the dereference
    # through rcx is still high confidence.
    eng = _engine([_x86_uaf(name="copied", via_copy=True), *_libc_stubs()])
    findings = cwe416.run(eng)
    assert len(findings) == 1
    assert findings[0].function == "copied"
    assert findings[0].confidence == "high"


def test_x86_call_between_free_and_use_abandons():
    # An intervening call breaks the intra-procedural contract -> no finding.
    base = 0x401500
    insns = [
        _Insn(base + 0x0, "call", hex(_MALLOC_ADDR)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0xA, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(base + 0xE, "call", hex(_FREE_ADDR)),
        _Insn(base + 0x13, "call", hex(_MALLOC_ADDR)),         # intervening call
        _Insn(base + 0x18, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0x1C, "mov", "byte ptr [rax], 0x58"),
        _Insn(base + 0x20, "ret", ""),
    ]
    eng = _engine([_Func(base, "interrupted", insns), *_libc_stubs()])
    assert cwe416.run(eng) == []


# ---------------------------------------------------------------------------
# AArch64 (AAPCS64) — the arch-aware path this change adds
# ---------------------------------------------------------------------------
#
# AArch64 -O0 codegen (as capstone renders it): the allocator result in `x0` is
# spilled with `str x0, [sp, #8]`; before `bl <free>` it is reloaded with
# `ldr x0, [sp, #8]`; after the free it is reloaded again and dereferenced
# through that base register (`str wzr, [x0]` / `ldr w0, [x0]`).


def _aarch64_uaf(base=0x210158, name="use_after_free", uses=True, via_copy=False):
    insns = [
        _Insn(base + 0x0, "mov", "x0, #0x20"),
        _Insn(base + 0x4, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x8, "str", "x0, [sp, #8]"),   # spill ptr to slot
        _Insn(base + 0xC, "ldr", "x0, [sp, #8]"),   # reload for free
        _Insn(base + 0x10, "bl", hex(_FREE_ADDR)),  # free
    ]
    if uses:
        if via_copy:
            insns += [
                _Insn(base + 0x14, "ldr", "x9, [sp, #8]"),   # reload into scratch
                _Insn(base + 0x18, "mov", "x10, x9"),        # copy alias
                _Insn(base + 0x1C, "str", "wzr, [x10]"),     # deref USE
            ]
        else:
            insns += [
                _Insn(base + 0x14, "ldr", "x9, [sp, #8]"),   # reload freed ptr
                _Insn(base + 0x18, "str", "wzr, [x9]"),      # deref USE
            ]
    insns.append(_Insn(base + 0x24, "ret", ""))
    return _Func(base, name, insns)


def test_aarch64_use_after_free_flagged():
    eng = _engine([_aarch64_uaf(), *_libc_stubs()], arch_name="AARCH64")
    findings = cwe416.run(eng)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 416
    assert f.function == "use_after_free"
    assert f.confidence == "high"
    assert f.address == 0x210158 + 0x18  # the deref `str wzr, [x9]`
    assert len(f.taint_trace) == 3


def test_aarch64_free_without_use_not_flagged():
    eng = _engine([_aarch64_uaf(uses=False), *_libc_stubs()], arch_name="AARCH64")
    assert cwe416.run(eng) == []


def test_aarch64_x29_frame_slot():
    # Frame-relative slot `[x29, #-8]` instead of `[sp, #N]`.
    base = 0x210300
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [x29, #-8]"),
        _Insn(base + 0x8, "ldr", "x0, [x29, #-8]"),
        _Insn(base + 0xC, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x10, "ldr", "x9, [x29, #-8]"),
        _Insn(base + 0x14, "str", "wzr, [x9]"),
        _Insn(base + 0x18, "ret", ""),
    ]
    eng = _engine([_Func(base, "framed", insns), *_libc_stubs()], arch_name="AARCH64")
    findings = cwe416.run(eng)
    assert len(findings) == 1 and findings[0].confidence == "high"


def test_aarch64_use_via_register_copy_still_high():
    # The slot is reloaded into x9 (confirmed alias) then copied into x10; the
    # copy inherits the confirmed-reload provenance, so the dereference through
    # x10 is still high confidence.
    eng = _engine(
        [_aarch64_uaf(name="copied", via_copy=True), *_libc_stubs()],
        arch_name="AARCH64",
    )
    findings = cwe416.run(eng)
    assert len(findings) == 1
    assert findings[0].function == "copied"
    assert findings[0].confidence == "high"


def test_aarch64_stack_slot_access_after_free_is_not_a_deref():
    # A plain reload from the stack slot (no dereference through the freed
    # pointer's base register) must NOT be mistaken for the use.
    base = 0x210600
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [sp, #8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #8]"),
        _Insn(base + 0xC, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x10, "ldr", "x9, [sp, #8]"),   # reloads the freed ptr value
        _Insn(base + 0x14, "str", "x9, [sp, #16]"),  # stores it to ANOTHER slot
        _Insn(base + 0x18, "ret", ""),               # ...no deref of the pointer
    ]
    eng = _engine([_Func(base, "no_deref", insns), *_libc_stubs()], arch_name="AARCH64")
    assert cwe416.run(eng) == []


def test_aarch64_call_between_free_and_use_abandons():
    base = 0x210700
    insns = [
        _Insn(base + 0x0, "bl", hex(_MALLOC_ADDR)),
        _Insn(base + 0x4, "str", "x0, [sp, #8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #8]"),
        _Insn(base + 0xC, "bl", hex(_FREE_ADDR)),
        _Insn(base + 0x10, "bl", hex(_MALLOC_ADDR)),  # intervening call
        _Insn(base + 0x14, "ldr", "x9, [sp, #8]"),
        _Insn(base + 0x18, "str", "wzr, [x9]"),
        _Insn(base + 0x1C, "ret", ""),
    ]
    eng = _engine([_Func(base, "interrupted", insns), *_libc_stubs()], arch_name="AARCH64")
    assert cwe416.run(eng) == []


def test_returns_empty_on_unsupported_arch():
    eng = _engine([_aarch64_uaf(), *_libc_stubs()], arch_name="MIPS32")
    assert cwe416.run(eng) == []
