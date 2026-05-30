"""Fast unit tests for the engine's CWE-401 unfreed-allocations helper.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises ``AngrEngine.unfreed_allocations``
without importing angr.

The synthetic instruction streams mirror -O0 x86_64 codegen (Intel syntax, as
capstone renders it):

    leak:        call malloc ; mov [rbp-8], rax ; ret
                 -> spilled but never freed/returned/escaped (CANDIDATE)
    free:        call malloc ; mov [rbp-8], rax ; mov rdi, [rbp-8]
                 ; call free ; ret
                 -> released via free (NOT a candidate)
    return:      call malloc ; mov [rbp-8], rax ; mov rax, [rbp-8] ; ret
                 -> ownership returned to caller (NOT a candidate)
    handoff:     call malloc ; mov [rbp-8], rax ; mov rdi, [rbp-8]
                 ; call other ; ret
                 -> handed to another function (NOT a candidate)
    stash:       call malloc ; mov [rbp-8], rax ; mov rax, [rbp-8]
                 ; mov [rip+global], rax ; ret
                 -> stored to a non-slot memory location (NOT a candidate)
"""

from __future__ import annotations

from autopsy.engine import AngrEngine


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding
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


_MALLOC = 0x500000
_CALLOC = 0x500010
_STRDUP = 0x500020
_GETENV = 0x500030
_FREE = 0x500040
_OTHER = 0x500050
_REALLOC = 0x500060

_SYMBOLS = {
    _MALLOC: "malloc",
    _CALLOC: "calloc",
    _STRDUP: "strdup",
    _GETENV: "getenv",
    _FREE: "free",
    _OTHER: "other",
    _REALLOC: "realloc",
}


# ---------------------------------------------------------------------------
# x86_64 fixtures
# ---------------------------------------------------------------------------


def _amd64_leak(base=0x401000, name="leaky"):
    """malloc -> spill -> ret. No release, no escape -> CANDIDATE."""
    return _Func(base, name, [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "nop", ""),
        _Insn(base + 0xA, "ret", ""),
    ])


def _amd64_free(base=0x401100, name="safe_free"):
    """malloc -> spill -> reload to rdi -> free -> ret. Released."""
    return _Func(base, name, [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "call", hex(_FREE)),
        _Insn(base + 0x12, "ret", ""),
    ])


def _amd64_return(base=0x401200, name="safe_return"):
    """malloc -> spill -> reload to rax -> ret. Ownership returned."""
    return _Func(base, name, [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "ret", ""),
    ])


def _amd64_handoff(base=0x401300, name="safe_handoff"):
    """malloc -> spill -> reload to rdi -> call other -> ret. Handed off."""
    return _Func(base, name, [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "call", hex(_OTHER)),
        _Insn(base + 0x12, "ret", ""),
    ])


def _amd64_stash(base=0x401400, name="safe_stash"):
    """malloc -> spill -> reload -> store to a non-slot memory location -> ret.
    The pointer is stashed somewhere persistent -> NOT a leak."""
    return _Func(base, name, [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "qword ptr [rip + 0x2000], rax"),
        _Insn(base + 0x14, "ret", ""),
    ])


# ---------------------------------------------------------------------------
# Tests — x86_64
# ---------------------------------------------------------------------------


def test_amd64_leak_detected():
    eng = _engine([_amd64_leak()], _SYMBOLS)
    sites = eng.unfreed_allocations()
    assert len(sites) == 1
    s = sites[0]
    assert s["function"] == "leaky"
    assert s["alloc_name"] == "malloc"
    assert s["alloc_address"] == 0x401000
    assert s["address"] == 0x401000
    assert s["slot"] == "rbp-8"


def test_amd64_free_not_flagged():
    """A free of the slot pointer suppresses the finding."""
    eng = _engine([_amd64_free()], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_realloc_treated_as_release():
    """realloc may free its first arg -> conservatively treat as a release."""
    base = 0x401500
    func = _Func(base, "via_realloc", [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rdi, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "call", hex(_REALLOC)),
        _Insn(base + 0x12, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_return_not_flagged():
    """A reload of the slot into rax before ret transfers ownership."""
    eng = _engine([_amd64_return()], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_handoff_not_flagged():
    """Passing the slot to another function in rdi transfers ownership."""
    eng = _engine([_amd64_handoff()], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_stash_not_flagged():
    """A store of the slot to a non-slot memory location is an escape."""
    eng = _engine([_amd64_stash()], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_result_never_spilled_skipped():
    """If the allocator result is never spilled, we conservatively skip it."""
    base = 0x401600
    func = _Func(base, "no_spill", [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        # rax used directly (e.g. as a return) without ever spilling.
        _Insn(base + 0x5, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    # The spill is required for our slot-tracking; without it we can't follow
    # the pointer, so we stay quiet (false-negative bias).
    assert eng.unfreed_allocations() == []


def test_amd64_getenv_is_not_owned():
    """getenv() returns env-owned storage — never flagged as a leak."""
    base = 0x401700
    func = _Func(base, "from_env", [
        _Insn(base + 0x0, "call", hex(_GETENV)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_each_owned_allocator_tracked():
    """Every owned allocator in the set produces a finding when leaked."""
    for stub, expected in ((_MALLOC, "malloc"),
                           (_CALLOC, "calloc"),
                           (_STRDUP, "strdup")):
        base = 0x402000
        func = _Func(base, "use", [
            _Insn(base + 0x0, "call", hex(stub)),
            _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
            _Insn(base + 0x9, "ret", ""),
        ])
        eng = _engine([func], _SYMBOLS)
        sites = eng.unfreed_allocations()
        assert len(sites) == 1, f"{expected} leak should be tracked"
        assert sites[0]["alloc_name"] == expected


def test_amd64_alias_via_register_copy_is_handoff():
    """Reg-copy of the reloaded slot into rdi before a call -> escape."""
    base = 0x402100
    func = _Func(base, "via_alias", [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "rdi, rax"),
        _Insn(base + 0x10, "call", hex(_OTHER)),
        _Insn(base + 0x15, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_plt_and_simprocedure_skipped():
    plt = _Func(0x403000, "malloc@plt",
                [_Insn(0x403000, "call", hex(_MALLOC))], is_plt=True)
    sim = _Func(0x403100, "sim",
                [_Insn(0x403100, "call", hex(_MALLOC))], is_simprocedure=True)
    eng = _engine([plt, sim], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_non_allocator_call_ignored():
    """A non-allocator call's return value is not tracked as a leak source."""
    base = 0x403200
    func = _Func(base, "not_alloc", [
        _Insn(base + 0x0, "call", hex(_OTHER)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(base + 0x9, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    assert eng.unfreed_allocations() == []


def test_amd64_multiple_functions_each_leaked_reported():
    eng = _engine(
        [_amd64_leak(0x404000, "a"), _amd64_leak(0x404100, "b")],
        _SYMBOLS,
    )
    sites = eng.unfreed_allocations()
    assert {s["function"] for s in sites} == {"a", "b"}


def test_amd64_safe_and_leaky_mix():
    """A leaky and a safe function in the same CFG: only the leaky one fires."""
    eng = _engine(
        [_amd64_leak(0x405000, "leaks"), _amd64_free(0x405100, "frees"),
         _amd64_return(0x405200, "returns")],
        _SYMBOLS,
    )
    sites = eng.unfreed_allocations()
    assert {s["function"] for s in sites} == {"leaks"}


def test_returns_empty_on_unsupported_arch():
    """On an arch without a CWE-401 walker, the engine returns []."""
    eng = _engine([_amd64_leak()], _SYMBOLS, arch_name="MIPS32")
    assert eng.unfreed_allocations() == []


# ---------------------------------------------------------------------------
# AArch64 (AAPCS64) fixtures
# ---------------------------------------------------------------------------


def _aarch64_leak(base=0x501000, name="leaky"):
    """bl malloc -> str x0, [sp, #8] -> ret. No release, no escape."""
    return _Func(base, name, [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "nop", ""),
        _Insn(base + 0xC, "ret", ""),
    ])


def _aarch64_free(base=0x501100, name="safe_free"):
    """bl malloc -> spill -> reload to x0 -> bl free -> ret."""
    return _Func(base, name, [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #0x8]"),
        _Insn(base + 0xC, "bl", hex(_FREE)),
        _Insn(base + 0x10, "ret", ""),
    ])


def _aarch64_return(base=0x501200, name="safe_return"):
    """bl malloc -> spill -> reload to x0 -> ret. Ownership returned."""
    return _Func(base, name, [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #0x8]"),
        _Insn(base + 0xC, "ret", ""),
    ])


def _aarch64_handoff(base=0x501300, name="safe_handoff"):
    """bl malloc -> spill -> reload to x0 -> bl other -> ret."""
    return _Func(base, name, [
        _Insn(base + 0x0, "bl", hex(_MALLOC)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "ldr", "x0, [sp, #0x8]"),
        _Insn(base + 0xC, "bl", hex(_OTHER)),
        _Insn(base + 0x10, "ret", ""),
    ])


# ---------------------------------------------------------------------------
# Tests — AArch64
# ---------------------------------------------------------------------------


def test_aarch64_leak_detected():
    eng = _engine([_aarch64_leak()], _SYMBOLS, arch_name="AARCH64")
    sites = eng.unfreed_allocations()
    assert len(sites) == 1
    s = sites[0]
    assert s["function"] == "leaky"
    assert s["alloc_name"] == "malloc"
    assert s["address"] == 0x501000
    # AArch64 slot key normalizes ``[sp, #0x8]`` to ``sp0x8`` (matches
    # the CWE-415/416/476 slot-key convention, which strips ``#`` and any
    # whitespace; the sign is preserved when present in the source operand).
    assert s["slot"] == "sp0x8"


def test_aarch64_free_not_flagged():
    eng = _engine([_aarch64_free()], _SYMBOLS, arch_name="AARCH64")
    assert eng.unfreed_allocations() == []


def test_aarch64_return_not_flagged():
    eng = _engine([_aarch64_return()], _SYMBOLS, arch_name="AARCH64")
    assert eng.unfreed_allocations() == []


def test_aarch64_handoff_not_flagged():
    eng = _engine([_aarch64_handoff()], _SYMBOLS, arch_name="AARCH64")
    assert eng.unfreed_allocations() == []


def test_amd64_leaky_with_intervening_arithmetic_still_detected():
    """``leaky()`` from the fixture reloads slot into rax, then mutates rax
    (``add $1, rax``) before ret — the mutation drops rax from the alias set
    so the return-escape heuristic doesn't suppress the (correctly-detected)
    leak. This is the canonical -O0 ``void leaky(void) { p[1] = 0; }`` shape.
    """
    base = 0x406000
    func = _Func(base, "leaky_arith", [
        _Insn(base + 0x0, "call", hex(_MALLOC)),
        _Insn(base + 0x5, "mov", "qword ptr [rbp - 8], rax"),
        # Reload + write through p[0]
        _Insn(base + 0x9, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0xD, "mov", "byte ptr [rax], 0x78"),
        # Reload + write through p[1] — `add` mutates rax so it stops
        # aliasing the slot.
        _Insn(base + 0x10, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(base + 0x14, "add", "rax, 1"),
        _Insn(base + 0x18, "mov", "byte ptr [rax], 0"),
        _Insn(base + 0x1B, "nop", ""),
        _Insn(base + 0x1C, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS)
    sites = eng.unfreed_allocations()
    assert len(sites) == 1, "the leak must be detected despite the trailing rax mutation"
    assert sites[0]["function"] == "leaky_arith"


def test_aarch64_getenv_not_owned():
    base = 0x501400
    func = _Func(base, "from_env", [
        _Insn(base + 0x0, "bl", hex(_GETENV)),
        _Insn(base + 0x4, "str", "x0, [sp, #0x8]"),
        _Insn(base + 0x8, "ret", ""),
    ])
    eng = _engine([func], _SYMBOLS, arch_name="AARCH64")
    assert eng.unfreed_allocations() == []
