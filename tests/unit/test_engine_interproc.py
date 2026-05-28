"""Fast unit tests for the engine's interprocedural CWE-416 helpers.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises ``in_binary_callees_freeing_arg``,
``_frees_incoming_arg``, ``callers_of``, and ``caller_uses_arg_after_call``
without importing angr.

The synthetic instructions mirror the -O0 x86_64 codegen of the
``cwe416-interproc-vuln`` fixture (Intel syntax, as capstone renders it):

    release(p):  mov [rbp - 8], rdi ; mov rax,[rbp - 8] ; mov rdi,rax ; call free
    run():       ... mov rax,[rbp - 8] ; mov rdi,rax ; call release
                 mov rax,[rbp - 8] ; movb [rax], 0x5a   (use-after-free)
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
        # Map call-target addresses to functions for _resolve_call_target.
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
    name = "AMD64"


class _Project:
    def __init__(self):
        self.arch = _Arch()
        self.loader = _Loader()


def _engine(funcs):
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project()
    eng._cfg = _Cfg(funcs)
    return eng


# Addresses chosen to mirror the fixture.
FREE_ADDR = 0x401030
RELEASE_ADDR = 0x401136
RUN_ADDR = 0x401151


def _free_plt():
    # A PLT stub named 'free'; _resolve_call_target maps the call target addr
    # to this function's name.
    return _Func(FREE_ADDR, "free", [], is_plt=True)


def _release_func():
    # Frees its incoming first argument (rdi spilled to [rbp - 8]).
    insns = [
        _Insn(RELEASE_ADDR + 0x8, "mov", "qword ptr [rbp - 8], rdi"),
        _Insn(RELEASE_ADDR + 0xC, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(RELEASE_ADDR + 0x10, "mov", "rdi, rax"),
        _Insn(RELEASE_ADDR + 0x13, "call", hex(FREE_ADDR)),
    ]
    return _Func(RELEASE_ADDR, "release", insns)


def _run_func(use=True):
    # Passes [rbp - 8] to release(), then (optionally) dereferences it.
    insns = [
        _Insn(RUN_ADDR + 0x32, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(RUN_ADDR + 0x36, "mov", "rdi, rax"),
        _Insn(RUN_ADDR + 0x39, "call", hex(RELEASE_ADDR)),
    ]
    if use:
        insns += [
            _Insn(RUN_ADDR + 0x3E, "mov", "rax, qword ptr [rbp - 8]"),
            _Insn(RUN_ADDR + 0x42, "mov", "byte ptr [rax], 0x5a"),
        ]
    return _Func(RUN_ADDR, "run", insns)


RUN_CALL_RELEASE_ADDR = RUN_ADDR + 0x39
RUN_USE_ADDR = RUN_ADDR + 0x42


# ---------------------------------------------------------------------------
# in_binary_callees_freeing_arg / _frees_incoming_arg
# ---------------------------------------------------------------------------


def test_release_detected_as_freeing_its_argument():
    eng = _engine([_free_plt(), _release_func(), _run_func()])
    assert "release" in eng.in_binary_callees_freeing_arg()


def test_plt_stub_not_reported_as_freeing_arg():
    eng = _engine([_free_plt(), _release_func(), _run_func()])
    # The 'free' PLT itself must not be reported.
    assert "free" not in eng.in_binary_callees_freeing_arg()


def test_function_freeing_local_alloc_not_reported():
    # A function that mallocs locally and frees that (not an incoming arg) is
    # not a cross-function-dangling source: there's no [rbp-N], rdi prologue
    # spill of a parameter feeding the free.
    insns = [
        _Insn(0x402000, "call", hex(0x401040)),          # call malloc@plt
        _Insn(0x402005, "mov", "qword ptr [rbp - 8], rax"),
        _Insn(0x402009, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(0x40200C, "mov", "rdi, rax"),
        _Insn(0x40200F, "call", hex(FREE_ADDR)),
    ]
    malloc_plt = _Func(0x401040, "malloc", [], is_plt=True)
    local = _Func(0x402000, "local_free", insns)
    eng = _engine([_free_plt(), malloc_plt, local])
    assert "local_free" not in eng.in_binary_callees_freeing_arg()


# ---------------------------------------------------------------------------
# callers_of
# ---------------------------------------------------------------------------


def test_callers_of_finds_run_calling_release():
    eng = _engine([_free_plt(), _release_func(), _run_func()])
    callers = eng.callers_of("release")
    assert len(callers) == 1
    assert callers[0].caller_function == "run"
    assert callers[0].call_address == RUN_CALL_RELEASE_ADDR
    assert callers[0].target_name == "release"


def test_callers_of_returns_empty_for_uncalled_function():
    eng = _engine([_free_plt(), _release_func(), _run_func()])
    assert eng.callers_of("nonexistent") == []


# ---------------------------------------------------------------------------
# caller_uses_arg_after_call
# ---------------------------------------------------------------------------


def test_caller_use_after_call_detected():
    eng = _engine([_free_plt(), _release_func(), _run_func(use=True)])
    use_addr = eng.caller_uses_arg_after_call("run", RUN_CALL_RELEASE_ADDR)
    assert use_addr == RUN_USE_ADDR


def test_caller_no_use_after_call_returns_none():
    eng = _engine([_free_plt(), _release_func(), _run_func(use=False)])
    assert eng.caller_uses_arg_after_call("run", RUN_CALL_RELEASE_ADDR) is None


def test_caller_use_after_intervening_call_not_reported():
    # If another call sits between the freeing call and the dereference, the
    # single-hop scope is broken — return None (conservative, no false positive).
    insns = [
        _Insn(0x403000, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(0x403004, "mov", "rdi, rax"),
        _Insn(0x403007, "call", hex(RELEASE_ADDR)),
        _Insn(0x40300C, "call", hex(FREE_ADDR)),       # intervening call
        _Insn(0x403011, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(0x403015, "mov", "byte ptr [rax], 0x5a"),
    ]
    caller = _Func(0x403000, "run2", insns)
    eng = _engine([_free_plt(), _release_func(), caller])
    assert eng.caller_uses_arg_after_call("run2", 0x403007) is None


def test_caller_use_returns_none_for_unknown_caller():
    eng = _engine([_free_plt(), _release_func(), _run_func()])
    assert eng.caller_uses_arg_after_call("ghost", 0x401234) is None


# ---------------------------------------------------------------------------
# caller_frees_arg_before_call (single-hop interprocedural CWE-415)
# ---------------------------------------------------------------------------
#
# These synthetic streams mirror the -O0 x86_64 codegen of the
# cwe415-interproc-vuln fixture's run():
#
#     call malloc ; mov [rbp-8], rax
#     mov rax,[rbp-8] ; mov rdi,rax ; call free      <- first free (caller)
#     mov rax,[rbp-8] ; mov rdi,rax ; call release   <- second free (callee)

MALLOC_ADDR = 0x401040
DF_RUN_ADDR = 0x401151


def _malloc_plt():
    return _Func(MALLOC_ADDR, "malloc", [], is_plt=True)


def _df_run_func(realloc_between=False, freed_first=True):
    """run(): mallocs p, (optionally) frees p, then passes p to release()."""
    insns = [
        _Insn(DF_RUN_ADDR + 0x8, "call", hex(MALLOC_ADDR)),
        _Insn(DF_RUN_ADDR + 0xD, "mov", "qword ptr [rbp - 8], rax"),
    ]
    if freed_first:
        insns += [
            _Insn(DF_RUN_ADDR + 0x1D, "mov", "rax, qword ptr [rbp - 8]"),
            _Insn(DF_RUN_ADDR + 0x21, "mov", "rdi, rax"),
            _Insn(DF_RUN_ADDR + 0x24, "call", hex(FREE_ADDR)),  # FIRST free
        ]
    if realloc_between:
        insns += [
            _Insn(DF_RUN_ADDR + 0x29, "call", hex(MALLOC_ADDR)),
            _Insn(DF_RUN_ADDR + 0x2E, "mov", "qword ptr [rbp - 8], rax"),  # realloc slot
        ]
    insns += [
        _Insn(DF_RUN_ADDR + 0x39, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(DF_RUN_ADDR + 0x3D, "mov", "rdi, rax"),
        _Insn(DF_RUN_ADDR + 0x40, "call", hex(RELEASE_ADDR)),  # SECOND free (callee)
    ]
    return _Func(DF_RUN_ADDR, "run", insns)


DF_FIRST_FREE_ADDR = DF_RUN_ADDR + 0x24
DF_RELEASE_CALL_ADDR = DF_RUN_ADDR + 0x40


def test_caller_freed_arg_before_handoff_detected():
    eng = _engine([_free_plt(), _malloc_plt(), _release_func(), _df_run_func()])
    addr = eng.caller_frees_arg_before_call("run", DF_RELEASE_CALL_ADDR)
    assert addr == DF_FIRST_FREE_ADDR


def test_caller_did_not_free_first_returns_none():
    eng = _engine(
        [_free_plt(), _malloc_plt(), _release_func(), _df_run_func(freed_first=False)]
    )
    assert eng.caller_frees_arg_before_call("run", DF_RELEASE_CALL_ADDR) is None


def test_reallocation_between_frees_cancels_candidate():
    # The slot is reallocated after the first free, so the second free targets
    # fresh memory — not a double-free. Conservative: return None.
    eng = _engine(
        [_free_plt(), _malloc_plt(), _release_func(),
         _df_run_func(realloc_between=True)]
    )
    assert eng.caller_frees_arg_before_call("run", DF_RELEASE_CALL_ADDR) is None


def test_caller_frees_returns_none_for_unknown_caller():
    eng = _engine([_free_plt(), _malloc_plt(), _release_func(), _df_run_func()])
    assert eng.caller_frees_arg_before_call("ghost", 0x401234) is None
