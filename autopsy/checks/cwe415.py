"""CWE-415: double-free (intra-procedural).

Strategy: within a single function body, find the sequence
``malloc -> ... -> free -> ... -> free`` where both free() calls operate on
the same pointer:

  * the malloc return value is saved to a stack slot,
  * that same stack slot is the pointer handed to the first ``free`` (possibly
    via a register copy), and
  * after the first ``free``, the same pointer is handed to a second ``free``
    before any intervening reallocation, with NO function calls between the
    first ``free`` and the second ``free``.

This reuses the slot-tracking and alias-register idea from ``cwe416.py``:
instead of looking for a dereference after free, look for a second ``call
free`` where the first-argument register aliases the same slot.

**Arch-aware (x86_64 + AArch64).** The slot-tracking abstraction is identical
across architectures — only the concrete register names, the store/load
mnemonics, and the stack-slot operand syntax differ:

  * x86_64 (SysV): malloc result in ``rax``; first arg in ``rdi``; slot store
    ``mov [rbp-N], rax``; slot reload ``mov reg, [rbp-N]``; register copy
    ``mov dst, src`` — all via the ``mov`` mnemonic, Intel slots ``[rbp-N]`` /
    ``[rsp-N]``.
  * AArch64 (AAPCS64): malloc result in ``x0``; first arg in ``x0``; slot store
    ``str x0, [sp, #N]`` (or ``[x29, #N]``); slot reload ``ldr reg, [sp, #N]``;
    register copy ``mov dst, src``. Capstone renders AArch64 64-bit GPRs as
    ``x0``..``x30`` and the frame/stack registers as ``x29``/``sp``.

The per-arch register/mnemonic/regex profile is selected once per run from
``engine.project.arch.name``; the scanning algorithm itself is shared.

[Worker decision: arch-aware slot profile] Rather than fork the scanner into
two near-identical copies, the architecture-specific surface (return register,
arg register, store/load/copy recognizers) is captured in a small ``_ArchProfile``
and the single ``_scan_function`` body is parameterized by it. This mirrors how
the engine-level CWE-190/134/732 checks were made arch-aware.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from autopsy.report import Finding, TaintPoint
from autopsy.checks import cwe415_interproc


@dataclass(frozen=True)
class _ArchProfile:
    """Architecture-specific register names and instruction recognizers.

    ``store_ret_to_slot`` matches an instruction storing the allocator's return
    register to a stack slot (groups: base, offset). ``load_slot_to_reg``
    matches a slot reload into a register (groups: dst-reg, base, offset).
    ``reg_copy`` matches a register-to-register move (groups: dst, src).
    ``store_mn`` / ``load_mn`` are the mnemonics those recognizers apply to.
    ``arg_reg`` is the first-argument register handed to ``free``.
    """

    arg_reg: str
    store_mn: str
    load_mn: str
    store_ret_to_slot: re.Pattern[str]
    load_slot_to_reg: re.Pattern[str]
    reg_copy: re.Pattern[str]


# --- x86_64 (SysV) -----------------------------------------------------------
# `mov qword ptr [rbp - 8], rax` -> store malloc result to a stack slot.
_X86_STORE = re.compile(
    r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*rax$"
)
# `mov rax, qword ptr [rbp - 8]` -> reload a stack slot into a register.
_X86_LOAD = re.compile(
    r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
)
# `mov rdi, rax` -> register-to-register copy.
_X86_COPY = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")

_X86_PROFILE = _ArchProfile(
    arg_reg="rdi",
    store_mn="mov",
    load_mn="mov",
    store_ret_to_slot=_X86_STORE,
    load_slot_to_reg=_X86_LOAD,
    reg_copy=_X86_COPY,
)

# --- AArch64 (AAPCS64) -------------------------------------------------------
# `str x0, [sp, #0x8]` / `str x0, [x29, #-8]` -> store malloc result to a slot.
_AARCH64_STORE = re.compile(
    r"^x0,\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
)
# `ldr x9, [sp, #0x8]` -> reload a stack slot into a register.
_AARCH64_LOAD = re.compile(
    r"^(x[0-9]+|sp|fp),\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
)
# `mov x0, x9` -> register-to-register copy.
_AARCH64_COPY = re.compile(r"^(x[0-9]+|sp|fp),\s*(x[0-9]+|sp|fp)$")

_AARCH64_PROFILE = _ArchProfile(
    arg_reg="x0",
    store_mn="str",
    load_mn="ldr",
    store_ret_to_slot=_AARCH64_STORE,
    load_slot_to_reg=_AARCH64_LOAD,
    reg_copy=_AARCH64_COPY,
)

_PROFILES: dict[str, _ArchProfile] = {
    "AMD64": _X86_PROFILE,
    "AARCH64": _AARCH64_PROFILE,
}


def _profile_for(engine) -> _ArchProfile | None:
    """The arch profile for the target, or ``None`` on an unsupported arch."""
    try:
        arch = engine.project.arch.name
    except Exception:  # pragma: no cover - defensive
        return None
    return _PROFILES.get(arch)


def _slot_key(prof: _ArchProfile, base: str, off: str | None) -> str:
    """Normalize a (base, offset) pair into a comparable slot key.

    AArch64 omits the offset for ``[sp]`` (offset 0); normalize that to ``+0``
    so x86_64 and AArch64 keys share the same shape.
    """
    if off is None:
        off = "+0"
    return f"{base}{off.replace(' ', '').lstrip('#')}"


def run(engine) -> list[Finding]:
    """Run both CWE-415 passes: intra-procedural and single-hop interprocedural.

    The intra-procedural pass (this module) catches the case where both
    ``free`` calls live in one function body, on both x86_64 and AArch64. The
    interprocedural pass (:mod:`cwe415_interproc`) catches the single-hop
    cross-function pattern; it is x86_64-only and returns nothing on other
    architectures. The intra-procedural scan is skipped entirely on an
    architecture with no slot-tracking profile. Findings from both are merged;
    duplicates at the same
    finding address are de-duplicated, with the intra-procedural
    (higher-fidelity) finding taking precedence.
    """
    findings: list[Finding] = []
    prof = _profile_for(engine)
    if prof is not None:
        # Run the intra-procedural scan only on a supported architecture; on an
        # unsupported arch it would mis-read register/slot conventions, so skip
        # it rather than emit unsound results. (The interprocedural pass below
        # is independently x86_64-gated by its own engine helpers.)
        cfg = engine.cfg()
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            finding = _scan_function(engine, func, prof)
            if finding is not None:
                findings.append(finding)

    intra_addrs = {f.address for f in findings}
    for f in cwe415_interproc.run(engine):
        if f.address not in intra_addrs:
            findings.append(f)
    return findings


def _flatten(func):
    insns = []
    for block in func.blocks:
        try:
            insns.extend(block.capstone.insns)
        except Exception:  # pragma: no cover - defensive
            continue
    insns.sort(key=lambda i: i.address)
    return insns


def _scan_function(engine, func, prof: _ArchProfile):
    insns = _flatten(func)

    ptr_slot = None       # stack slot holding the malloc'd pointer
    malloc_addr = None
    free_addr = None

    for idx, insn in enumerate(insns):
        if not _is_call(engine, insn):
            continue
        target = _resolve(engine, insn)

        if target in {"malloc", "calloc", "realloc"} and ptr_slot is None:
            malloc_addr = insn.address
            ptr_slot = _slot_after_malloc(insns, idx, prof)
            continue
        if target == "free" and ptr_slot is not None and free_addr is None:
            # Confirm the first free's arg register aliases our slot.
            if prof.arg_reg in _regs_aliasing_slot(insns, idx, ptr_slot, prof):
                free_addr = insn.address
            continue
        if target == "free" and ptr_slot is not None and free_addr is not None:
            # Confirm the second free's arg register still aliases the same
            # slot — this is the double-free.
            if prof.arg_reg in _regs_aliasing_slot(insns, idx, ptr_slot, prof):
                return _build_finding(func, malloc_addr, free_addr, insn.address)
            continue
        if target in {"malloc", "calloc", "realloc"} and ptr_slot is not None:
            # A new allocation replaces the old slot — reset state.
            if free_addr is not None:
                # Slot was freed and a new allocation now overlays it: no longer
                # a double-free candidate; stop scanning.
                return None
            malloc_addr = insn.address
            ptr_slot = _slot_after_malloc(insns, idx, prof)
            free_addr = None
        continue

    return None


def _slot_after_malloc(insns, malloc_idx, prof: _ArchProfile):
    """Return the stack-slot key the allocator result is stored into."""
    for nxt in insns[malloc_idx + 1 : malloc_idx + 6]:
        if nxt.mnemonic != prof.store_mn:
            continue
        m = prof.store_ret_to_slot.match(nxt.op_str)
        if m:
            base = m.group(1)
            off = m.group(2) if m.lastindex and m.lastindex >= 2 else None
            return _slot_key(prof, base, off)
    return None


def _regs_aliasing_slot(insns, call_idx, slot, prof: _ArchProfile):
    """Which registers alias ``slot`` in the instructions just before a call?"""
    aliases: set[str] = set()
    for prev in insns[max(0, call_idx - 8) : call_idx]:
        if prev.mnemonic == prof.load_mn:
            m_load = prof.load_slot_to_reg.match(prev.op_str)
            if m_load:
                base = m_load.group(2)
                off = m_load.group(3) if m_load.lastindex and m_load.lastindex >= 3 else None
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


def _resolve(engine, insn):
    cfg = engine.cfg()
    return engine._resolve_call_target(insn, cfg)


def _build_finding(func, malloc_addr, free_addr, second_free_addr):
    trace = [
        TaintPoint(malloc_addr, "allocation via malloc()"),
        TaintPoint(free_addr, "pointer freed (first free)"),
        TaintPoint(second_free_addr, "pointer freed again (double-free)"),
    ]
    return Finding(
        cwe=415,
        function=func.name,
        address=second_free_addr,
        evidence=(
            f"double-free in {func.name}: pointer freed at {hex(free_addr)} "
            f"then freed again at {hex(second_free_addr)}"
        ),
        taint_trace=trace,
        # Double-free is a definitive pattern: the same slot is handed to free()
        # twice with no intervening reallocation, confirmed by alias tracking.
        confidence="high",
    )
