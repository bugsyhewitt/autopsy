"""Fast unit tests for the engine's CWE-134 format-string sink helper.

angr-free. ``AngrEngine`` is built via ``__new__`` (bypassing the angr-loading
``__init__``) and handed a synthetic CFG whose blocks expose capstone-style
instruction objects. This exercises
``AngrEngine.format_string_sinks_with_nonliteral_format`` without importing angr.

The synthetic instruction streams mirror the -O0 x86_64 codegen of the
``cwe134-vuln`` fixture (Intel syntax, as capstone renders it):

    emit(p):     mov [rbp-8], rdi ; mov rax,[rbp-8] ; mov rdi,rax ; call printf
                 -> format reg rdi reloaded from a stack slot (VULNERABLE)
    log_line(p): mov [rbp-8], rdi ; mov rax,[rbp-8]
                 lea rdx,[rip+0xea7] ; mov rsi,rax ; mov rdi,rdx ; call printf
                 -> format reg rdi sourced from a lea rodata pointer (SAFE)
"""

from __future__ import annotations

from autopsy.engine import AngrEngine


# ---------------------------------------------------------------------------
# Synthetic capstone-style scaffolding (mirrors test_engine_interproc.py)
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


# Addresses chosen to mirror the fixture.
PRINTF_ADDR = 0x401030
EMIT_ADDR = 0x401170
LOG_ADDR = 0x401146
SNPRINTF_ADDR = 0x401040


def _printf_plt():
    return _Func(PRINTF_ADDR, "printf", [], is_plt=True)


def _snprintf_plt():
    return _Func(SNPRINTF_ADDR, "snprintf", [], is_plt=True)


def _emit_func():
    """emit(p): printf(user) — format reg rdi reloaded from a stack slot."""
    insns = [
        _Insn(EMIT_ADDR + 0x8, "mov", "qword ptr [rbp - 8], rdi"),
        _Insn(EMIT_ADDR + 0xC, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(EMIT_ADDR + 0x10, "mov", "rdi, rax"),
        _Insn(EMIT_ADDR + 0x13, "mov", "eax, 0"),
        _Insn(EMIT_ADDR + 0x18, "call", hex(PRINTF_ADDR)),
    ]
    return _Func(EMIT_ADDR, "emit", insns)


def _log_func():
    """log_line(p): printf("log: %s", user) — format reg from a lea rodata ptr."""
    insns = [
        _Insn(LOG_ADDR + 0x8, "mov", "qword ptr [rbp - 8], rdi"),
        _Insn(LOG_ADDR + 0xC, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(LOG_ADDR + 0x10, "lea", "rdx, [rip + 0xea7]"),
        _Insn(LOG_ADDR + 0x17, "mov", "rsi, rax"),
        _Insn(LOG_ADDR + 0x1A, "mov", "rdi, rdx"),
        _Insn(LOG_ADDR + 0x1D, "mov", "eax, 0"),
        _Insn(LOG_ADDR + 0x22, "call", hex(PRINTF_ADDR)),
    ]
    return _Func(LOG_ADDR, "log_line", insns)


EMIT_CALL_ADDR = EMIT_ADDR + 0x18


# ---------------------------------------------------------------------------
# format_string_sinks_with_nonliteral_format
# ---------------------------------------------------------------------------


def test_nonliteral_printf_detected():
    eng = _engine([_printf_plt(), _emit_func(), _log_func()])
    sinks = eng.format_string_sinks_with_nonliteral_format()
    funcs = {s["function"] for s in sinks}
    assert "emit" in funcs


def test_literal_printf_not_flagged():
    """log_line's printf uses a lea rodata format pointer — must NOT be flagged."""
    eng = _engine([_printf_plt(), _emit_func(), _log_func()])
    sinks = eng.format_string_sinks_with_nonliteral_format()
    funcs = {s["function"] for s in sinks}
    assert "log_line" not in funcs


def test_sink_record_fields():
    eng = _engine([_printf_plt(), _emit_func(), _log_func()])
    sinks = eng.format_string_sinks_with_nonliteral_format()
    emit = next(s for s in sinks if s["function"] == "emit")
    assert emit["sink_name"] == "printf"
    assert emit["fmt_reg"] == "rdi"
    assert emit["call_address"] == EMIT_CALL_ADDR
    assert emit["fmt_slot"] == "rbp-8"


def test_snprintf_uses_third_arg_register_rdx():
    """snprintf(buf, size, fmt): the format argument is rdx (third arg)."""
    insns = [
        # rdx (fmt) reloaded from a stack slot -> non-literal
        _Insn(0x402000, "mov", "rdx, qword ptr [rbp - 0x18]"),
        _Insn(0x402004, "mov", "rsi, 0x80"),
        _Insn(0x402008, "lea", "rdi, [rbp - 0x90]"),
        _Insn(0x40200C, "call", hex(SNPRINTF_ADDR)),
    ]
    func = _Func(0x402000, "fmt_into_buf", insns)
    eng = _engine([_snprintf_plt(), func])
    sinks = eng.format_string_sinks_with_nonliteral_format()
    assert len(sinks) == 1
    assert sinks[0]["sink_name"] == "snprintf"
    assert sinks[0]["fmt_reg"] == "rdx"
    assert sinks[0]["fmt_slot"] == "rbp-0x18"


def test_snprintf_literal_third_arg_not_flagged():
    """snprintf with a lea rodata format pointer in rdx is safe."""
    insns = [
        _Insn(0x403000, "lea", "rdx, [rip + 0x100]"),
        _Insn(0x403007, "mov", "rsi, 0x80"),
        _Insn(0x40300B, "lea", "rdi, [rbp - 0x90]"),
        _Insn(0x40300F, "call", hex(SNPRINTF_ADDR)),
    ]
    func = _Func(0x403000, "safe_fmt", insns)
    eng = _engine([_snprintf_plt(), func])
    assert eng.format_string_sinks_with_nonliteral_format() == []


def test_plt_stub_itself_not_scanned():
    """The printf PLT stub must not appear as a caller-side finding."""
    eng = _engine([_printf_plt(), _emit_func()])
    sinks = eng.format_string_sinks_with_nonliteral_format()
    assert all(s["function"] != "printf" for s in sinks)


def test_returns_empty_on_non_amd64():
    """The register-level helper is x86_64-only; returns [] on AArch64."""
    eng = _engine([_printf_plt(), _emit_func()], arch_name="AARCH64")
    assert eng.format_string_sinks_with_nonliteral_format() == []


def test_no_format_sinks_returns_empty():
    """A program with no printf-family calls yields no sinks."""
    insns = [
        _Insn(0x404000, "mov", "rax, qword ptr [rbp - 8]"),
        _Insn(0x404004, "ret", ""),
    ]
    func = _Func(0x404000, "noop", insns)
    eng = _engine([func])
    assert eng.format_string_sinks_with_nonliteral_format() == []
