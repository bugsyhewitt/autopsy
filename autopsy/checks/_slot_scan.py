"""Shared slot-tracking primitives for intra-procedural heap-pointer checks.

Both CWE-415 (double-free) and CWE-416 (use-after-free) share the same
allocation/free/stack-slot-aliasing machinery: they locate the stack slot that
the allocator result is spilled into, follow alias propagation through slot
reloads and register copies, and then verify a condition on what happens after
the free.  The architecture-specific surface (register names, mnemonics, regex
patterns) is captured in :class:`_ArchProfile` so the scanning algorithm can be
shared without forking.

Exported symbols used by cwe415 and cwe416:
  _ArchProfile           — arch-specific register/mnemonic/pattern bundle
  _X86_STORE/LOAD/COPY  — compiled regex patterns for x86_64
  _AARCH64_STORE/LOAD/COPY — compiled regex patterns for AArch64
  _profile_for(engine, profiles) — look up the profile for the target arch
  _slot_key(prof, base, off)    — normalize a stack-slot operand to a key
  _flatten(func)                — collect and sort all Capstone instructions
  _slot_after_malloc(...)       — find the slot the allocator result lands in
  _regs_aliasing_slot(...)      — which registers alias a slot before a call
  _is_call(engine, insn)        — arch-aware direct-call predicate
  _resolve(engine, insn)        — resolve a call's target to a symbol name
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class _ArchProfile:
    """Architecture-specific register names and instruction recognizers.

    ``store_ret_to_slot`` matches an instruction storing the allocator's return
    register to a stack slot (groups: base, offset). ``load_slot_to_reg``
    matches a slot reload into a register (groups: dst-reg, base, offset).
    ``reg_copy`` matches a register-to-register move (groups: dst, src).
    ``store_mn`` / ``load_mn`` are the mnemonics those recognizers apply to.
    ``arg_reg`` is the first-argument register handed to ``free``.
    ``deref_base`` (optional) matches a memory dereference through a register
    base (group: base reg); set by CWE-416 profiles to detect use-after-free.
    """

    arg_reg: str
    store_mn: str
    load_mn: str
    store_ret_to_slot: re.Pattern[str]
    load_slot_to_reg: re.Pattern[str]
    reg_copy: re.Pattern[str]
    deref_base: re.Pattern[str] | None = None


# ---------------------------------------------------------------------------
# Shared compiled regex patterns
# ---------------------------------------------------------------------------

# --- x86_64 (SysV) ---------------------------------------------------------
# ``mov qword ptr [rbp - 8], rax`` — store malloc result to a stack slot.
_X86_STORE = re.compile(
    r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*rax$"
)
# ``mov rax, qword ptr [rbp - 8]`` — reload a stack slot into a register.
_X86_LOAD = re.compile(
    r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
)
# ``mov rdi, rax`` — register-to-register copy.
_X86_COPY = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")
# Memory dereference through a register base: ``[rax]``, ``[rax + 4]``, etc.
_X86_DEREF = re.compile(r"\[(r[a-z0-9]+)")

# --- AArch64 (AAPCS64) -----------------------------------------------------
# ``str x0, [sp, #0x8]`` / ``str x0, [x29, #-8]`` — store malloc result.
_AARCH64_STORE = re.compile(
    r"^x0,\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
)
# ``ldr x9, [sp, #0x8]`` — reload a stack slot into a register.
_AARCH64_LOAD = re.compile(
    r"^(x[0-9]+|sp|fp),\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
)
# ``mov x0, x9`` — register-to-register copy.
_AARCH64_COPY = re.compile(r"^(x[0-9]+|sp|fp),\s*(x[0-9]+|sp|fp)$")
# Dereference through a register base: ``str wzr, [x9]``, ``ldr w0, [x9, #4]``.
# The base register is the first GPR inside the bracketed memory operand; the
# stack/frame registers (sp/x29/fp) are excluded so a stack-slot access (which
# is NOT a dereference of the freed heap pointer) does not look like the use.
_AARCH64_DEREF = re.compile(r"\[(x[0-9]+)(?!\d)")


# ---------------------------------------------------------------------------
# Shared helper functions
# ---------------------------------------------------------------------------

def _profile_for(engine, profiles: dict[str, _ArchProfile]) -> _ArchProfile | None:
    """Return the arch profile for the target binary, or ``None`` if unsupported.

    ``profiles`` is either the CWE-415 profile table (no ``deref_base``) or
    the CWE-416 profile table (with ``deref_base``), as appropriate for the
    calling check.
    """
    try:
        arch = engine.project.arch.name
    except Exception:  # pragma: no cover - defensive
        return None
    return profiles.get(arch)


def _slot_key(prof: _ArchProfile, base: str, off: str | None) -> str:
    """Normalize a (base, offset) pair into a comparable slot key.

    AArch64 omits the offset for ``[sp]`` (offset 0); normalize that to ``+0``
    so x86_64 and AArch64 keys share the same shape.
    """
    if off is None:
        off = "+0"
    return f"{base}{off.replace(' ', '').lstrip('#')}"


def _flatten(func) -> list:
    """Collect and sort all Capstone instructions from a CFG function object."""
    insns = []
    for block in func.blocks:
        try:
            insns.extend(block.capstone.insns)
        except Exception:  # pragma: no cover - defensive
            continue
    insns.sort(key=lambda i: i.address)
    return insns


def _slot_after_malloc(insns: list, malloc_idx: int, prof: _ArchProfile) -> str | None:
    """Return the stack-slot key the allocator result is stored into.

    Scans the few instructions after the allocator call for a store of the
    return register into a stack slot.  Returns the normalized slot key, or
    ``None`` if no such store is found within the look-ahead window.
    """
    for nxt in insns[malloc_idx + 1 : malloc_idx + 6]:
        if nxt.mnemonic != prof.store_mn:
            continue
        m = prof.store_ret_to_slot.match(nxt.op_str)
        if m:
            base = m.group(1)
            off = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            return _slot_key(prof, base, off)
    return None


def _regs_aliasing_slot(
    insns: list, call_idx: int, slot: str, prof: _ArchProfile
) -> set[str]:
    """Which registers alias ``slot`` in the instructions just before a call?

    Walks back a short window before ``insns[call_idx]``, tracking slot reloads
    (``load_mn`` instruction matching ``load_slot_to_reg``) and register copies
    (``mov dst, src`` where ``src`` is already an alias).  Returns the set of
    register names that currently alias ``slot``.
    """
    aliases: set[str] = set()
    for prev in insns[max(0, call_idx - 8) : call_idx]:
        if prev.mnemonic == prof.load_mn:
            m_load = prof.load_slot_to_reg.match(prev.op_str)
            if m_load:
                base = m_load.group(2)
                off = (
                    m_load.group(3)
                    if m_load.lastindex and m_load.lastindex >= 3
                    else None
                )
                if _slot_key(prof, base, off) == slot:
                    aliases.add(m_load.group(1))
                    continue
        if prev.mnemonic == "mov":
            m_copy = prof.reg_copy.match(prev.op_str)
            if m_copy and m_copy.group(2) in aliases:
                aliases.add(m_copy.group(1))
    return aliases


def _is_call(engine, insn) -> bool:
    """True if ``insn`` is a direct call on the target architecture."""
    try:
        return insn.mnemonic in engine._call_mnemonics()
    except Exception:  # pragma: no cover - defensive
        return insn.mnemonic == "call"


def _resolve(engine, insn) -> str | None:
    """Resolve a call instruction's target to an imported symbol name."""
    cfg = engine.cfg()
    return engine._resolve_call_target(insn, cfg)
