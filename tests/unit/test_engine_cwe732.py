"""Fast unit tests for the engine's CWE-732 permission-assignment helpers.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises
``AngrEngine.chmod_calls_with_permissive_mode`` and
``AngrEngine.umask_calls_with_permissive_mask`` without importing angr.

The synthetic streams mirror -O0 x86_64 codegen (Intel syntax, as capstone
renders it): the mode/mask literal is materialized into the 32-bit sub-register
(esi/edx/edi) just before the call, e.g. ``mov esi, 0x1ff ; call chmod``.
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


# A chmod/umask call resolves its target via a PLT stub function whose name is
# the symbol; model that as a named function at the call's target address.
def _funcs_with_sink(caller, sink_name, sink_addr=0x402000):
    sink = _Func(sink_addr, sink_name, [_Insn(sink_addr, "jmp", "0x0")], is_plt=True)
    return [caller, sink]


def _chmod_func(mode_hex, mode_reg="esi", base=0x401100, name="setup",
                sink="chmod", sink_addr=0x402000):
    """A function that sets the mode register to an immediate then calls a sink."""
    insns = [
        _Insn(base + 0x0, "mov", "edi, dword ptr [rbp - 8]"),   # path/fd arg
        _Insn(base + 0x4, "mov", f"{mode_reg}, {mode_hex}"),    # mode literal
        _Insn(base + 0x9, "call", hex(sink_addr)),
        _Insn(base + 0xE, "ret", ""),
    ]
    return _Func(base, name, insns), sink_addr, sink


# ---------------------------------------------------------------------------
# chmod-family
# ---------------------------------------------------------------------------


def test_chmod_0777_flagged():
    caller, sink_addr, sink = _chmod_func("0x1ff")  # 0o777
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    sites = eng.chmod_calls_with_permissive_mode()
    assert len(sites) == 1
    assert sites[0]["function"] == "setup"
    assert sites[0]["sink_name"] == "chmod"
    assert sites[0]["mode"] == 0o777
    assert sites[0]["address"] == 0x401100 + 0x9


def test_chmod_0666_flagged():
    caller, sink_addr, sink = _chmod_func("0x1b6")  # 0o666
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    sites = eng.chmod_calls_with_permissive_mode()
    assert len(sites) == 1 and sites[0]["mode"] == 0o666


def test_chmod_owner_only_not_flagged():
    # 0o600 = 0x180: neither group-write (0o020) nor world-write (0o002) -> safe.
    caller, sink_addr, sink = _chmod_func("0x180")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    assert eng.chmod_calls_with_permissive_mode() == []


def test_chmod_owner_rwx_only_not_flagged():
    # 0o700 = 0x1c0: owner rwx only, group/other empty -> safe.
    caller, sink_addr, sink = _chmod_func("0x1c0")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    assert eng.chmod_calls_with_permissive_mode() == []


def test_chmod_group_write_only_flagged():
    # 0o620 = 0x190: group-write set -> beyond owner -> flagged.
    caller, sink_addr, sink = _chmod_func("0x190")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    sites = eng.chmod_calls_with_permissive_mode()
    assert len(sites) == 1 and sites[0]["mode"] == 0o620


def test_chmod_decimal_immediate_flagged():
    # capstone sometimes renders small immediates in decimal; 511 == 0o777.
    caller, sink_addr, sink = _chmod_func("511")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    sites = eng.chmod_calls_with_permissive_mode()
    assert len(sites) == 1 and sites[0]["mode"] == 0o777


def test_fchmodat_uses_rdx_mode_register():
    # fchmodat(dirfd, path, mode, flags): mode is in rdx/edx.
    caller, sink_addr, sink = _chmod_func("0x1ff", mode_reg="edx",
                                          sink="fchmodat", name="recurse")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr))
    sites = eng.chmod_calls_with_permissive_mode()
    assert len(sites) == 1
    assert sites[0]["sink_name"] == "fchmodat"
    assert sites[0]["mode"] == 0o777


def test_chmod_runtime_mode_not_flagged():
    # Mode loaded from a stack slot is a runtime value -> not flagged.
    base = 0x401300
    sink_addr = 0x402000
    insns = [
        _Insn(base + 0x0, "mov", "esi, dword ptr [rbp - 4]"),  # mode from a slot
        _Insn(base + 0x4, "call", hex(sink_addr)),
    ]
    caller = _Func(base, "dynamic", insns)
    sink = _Func(sink_addr, "chmod", [_Insn(sink_addr, "jmp", "0x0")], is_plt=True)
    eng = _engine([caller, sink])
    assert eng.chmod_calls_with_permissive_mode() == []


def test_chmod_returns_empty_on_non_amd64():
    caller, sink_addr, sink = _chmod_func("0x1ff")
    eng = _engine(_funcs_with_sink(caller, sink, sink_addr), arch_name="AARCH64")
    assert eng.chmod_calls_with_permissive_mode() == []


def test_plt_and_simprocedure_callers_skipped():
    # The caller scanning must skip PLT/simprocedure bodies.
    plt = _Func(0x401400, "chmod@plt",
                [_Insn(0x401400, "mov", "esi, 0x1ff"),
                 _Insn(0x401405, "call", "0x402000")], is_plt=True)
    sink = _Func(0x402000, "chmod", [_Insn(0x402000, "jmp", "0x0")], is_plt=True)
    eng = _engine([plt, sink])
    assert eng.chmod_calls_with_permissive_mode() == []


# ---------------------------------------------------------------------------
# umask
# ---------------------------------------------------------------------------


def _umask_func(mask_hex, base=0x401500, name="init", sink_addr=0x402100):
    insns = [
        _Insn(base + 0x0, "mov", f"edi, {mask_hex}"),
        _Insn(base + 0x5, "call", hex(sink_addr)),
        _Insn(base + 0xA, "ret", ""),
    ]
    caller = _Func(base, name, insns)
    sink = _Func(sink_addr, "umask", [_Insn(sink_addr, "jmp", "0x0")], is_plt=True)
    return [caller, sink], base + 0x5


def test_umask_zero_flagged():
    funcs, call_addr = _umask_func("0x0")
    eng = _engine(funcs)
    sites = eng.umask_calls_with_permissive_mask()
    assert len(sites) == 1
    assert sites[0]["sink_name"] == "umask"
    assert sites[0]["mode"] == 0
    assert sites[0]["address"] == call_addr


def test_umask_partial_mask_flagged():
    # 0o002 strips only world-write; group-write (0o020) left unmasked -> flagged.
    funcs, _ = _umask_func("0x2")
    eng = _engine(funcs)
    assert len(eng.umask_calls_with_permissive_mask()) == 1


def test_umask_0022_not_flagged():
    # 0o022 strips both group- and world-write -> safe.
    funcs, _ = _umask_func("0x12")  # 0o022
    eng = _engine(funcs)
    assert eng.umask_calls_with_permissive_mask() == []


def test_umask_0077_not_flagged():
    # 0o077 strips all group/other bits -> safe.
    funcs, _ = _umask_func("0x3f")  # 0o077
    eng = _engine(funcs)
    assert eng.umask_calls_with_permissive_mask() == []


def test_umask_runtime_mask_not_flagged():
    base = 0x401600
    sink_addr = 0x402100
    insns = [
        _Insn(base + 0x0, "mov", "edi, dword ptr [rbp - 4]"),
        _Insn(base + 0x4, "call", hex(sink_addr)),
    ]
    caller = _Func(base, "dynmask", insns)
    sink = _Func(sink_addr, "umask", [_Insn(sink_addr, "jmp", "0x0")], is_plt=True)
    eng = _engine([caller, sink])
    assert eng.umask_calls_with_permissive_mask() == []


def test_umask_returns_empty_on_non_amd64():
    funcs, _ = _umask_func("0x0")
    eng = _engine(funcs, arch_name="AARCH64")
    assert eng.umask_calls_with_permissive_mask() == []
