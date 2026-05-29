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


def test_returns_empty_on_non_amd64():
    eng = _engine([_unchecked_malloc()], _SYMBOLS, arch_name="AARCH64")
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
