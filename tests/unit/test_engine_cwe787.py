"""Fast unit tests for the engine's CWE-787 literal-length resolver. angr-free.

These exercise ``AngrEngine.copy_call_length_is_literal`` — the helper that
decides whether a bulk-copy sink's length argument is a compile-time immediate
(and therefore cannot be attacker-controlled). ``AngrEngine`` is instantiated
via ``__new__`` (bypassing the angr-loading ``__init__``) and given a tiny fake
project + CFG whose functions yield fake capstone-shaped instructions.

The fixtures mirror real -O0 x86_64 codegen:

  clean baseline strncpy(p, line, 63):
      mov edx, 0x3f            ; length is a literal immediate
      ...
      call strncpy@plt         ; -> length_is_literal == True

  cwe787-vuln memcpy(buf, src, length):
      mov eax, [rbp - 0x118]   ; length reloaded from a (tainted) stack slot
      movsxd rdx, eax
      ...
      call memcpy@plt          ; -> length_is_literal == False
"""

import pytest

from autopsy.engine import AngrEngine


# ---------------------------------------------------------------------------
# Fake capstone / CFG scaffolding
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
    def __init__(self, insns):
        self.capstone = _Capstone(insns)


class _Func:
    def __init__(self, name, insns):
        self.name = name
        self.is_plt = False
        self.is_simprocedure = False
        self.blocks = [_Block(insns)]


class _Functions:
    def __init__(self, funcs):
        self._funcs = funcs

    def values(self):
        return self._funcs


class _KB:
    def __init__(self, funcs):
        self.functions = _Functions(funcs)


class _CFG:
    def __init__(self, funcs):
        self.kb = _KB(funcs)


class _Arch:
    def __init__(self, name):
        self.name = name


class _Project:
    def __init__(self, arch_name):
        self.arch = _Arch(arch_name)


def _engine(arch_name, funcs):
    eng = AngrEngine.__new__(AngrEngine)
    eng.project = _Project(arch_name)
    eng._cfg = _CFG(funcs)
    return eng


def _insns(seq):
    """seq: list of (addr, mnemonic, op_str)."""
    return [_Insn(a, m, o) for (a, m, o) in seq]


# ---------------------------------------------------------------------------
# Literal length -> True (suppress the false positive)
# ---------------------------------------------------------------------------


def test_immediate_length_is_literal():
    # strncpy(p, line, 63): mov edx, 0x3f ; call strncpy
    func = _Func("main", _insns([
        (0x100, "mov", "edx, 0x3f"),
        (0x104, "mov", "rsi, rcx"),
        (0x107, "mov", "rdi, rax"),
        (0x10a, "call", "0x401040"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("main", 0x10a, "strncpy") is True


def test_decimal_immediate_length_is_literal():
    func = _Func("f", _insns([
        (0x200, "mov", "rdx, 16"),
        (0x204, "call", "0x401050"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("f", 0x204, "memcpy") is True


def test_immediate_through_register_copy_is_literal():
    # mov rax, 0x10 ; mov rdx, rax ; call memcpy -> literal via alias chain.
    func = _Func("f", _insns([
        (0x300, "mov", "rax, 0x10"),
        (0x304, "mov", "rdx, rax"),
        (0x307, "call", "0x401050"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("f", 0x307, "memcpy") is True


# ---------------------------------------------------------------------------
# Non-literal length -> False (genuine, possibly-tainted copy still fires)
# ---------------------------------------------------------------------------


def test_stack_slot_length_is_not_literal():
    # memcpy(buf, src, length): movsxd rdx, eax <- mov eax, [rbp - 0x118].
    func = _Func("copy_to_heap", _insns([
        (0x400, "mov", "eax, dword ptr [rbp - 0x118]"),
        (0x406, "movsxd", "rdx, eax"),
        (0x409, "lea", "rcx, [rbp - 0x110]"),
        (0x410, "mov", "rsi, rcx"),
        (0x413, "mov", "rdi, rax"),
        (0x416, "call", "0x401050"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("copy_to_heap", 0x416, "memcpy") is False


def test_strcpy_has_no_length_arg_never_literal():
    # strcpy has no explicit length; it must never be classed as literal-length.
    func = _Func("f", _insns([
        (0x500, "mov", "rdx, 0x3f"),  # unrelated rdx set
        (0x504, "call", "0x401060"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("f", 0x504, "strcpy") is False


def test_unresolved_length_is_not_literal():
    # No discernible set of rdx before the call -> conservative False.
    func = _Func("f", _insns([
        (0x600, "nop", ""),
        (0x601, "call", "0x401050"),
    ]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("f", 0x601, "memcpy") is False


# ---------------------------------------------------------------------------
# Arch + edge cases
# ---------------------------------------------------------------------------


def test_non_amd64_returns_false():
    func = _Func("f", _insns([
        (0x700, "mov", "x2, 0x3f"),
        (0x704, "bl", "#0x401050"),
    ]))
    eng = _engine("AARCH64", [func])
    # AArch64 is not handled (register checks are arch-gated upstream).
    assert eng.copy_call_length_is_literal("f", 0x704, "memcpy") is False


def test_missing_function_returns_false():
    eng = _engine("AMD64", [_Func("other", _insns([(0x800, "ret", "")]))])
    assert eng.copy_call_length_is_literal("absent", 0x800, "memcpy") is False


def test_missing_call_address_returns_false():
    func = _Func("f", _insns([(0x900, "mov", "rdx, 0x3f"), (0x904, "call", "0x401050")]))
    eng = _engine("AMD64", [func])
    assert eng.copy_call_length_is_literal("f", 0xdead, "memcpy") is False
