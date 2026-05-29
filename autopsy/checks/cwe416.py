"""CWE-416: use-after-free (intra-procedural).

Strategy: within a single function body, find the sequence
``malloc -> ... -> free -> ... -> use`` where:

  * the malloc return value is saved to a stack slot,
  * that same stack slot is the pointer handed to ``free`` (possibly via a
    register copy), and
  * after the ``free`` call, the same pointer (reloaded from the stack slot)
    is dereferenced (a memory read/write through it), with NO function call
    between the ``free`` and the dereference.

This matches the v0.1 fixture contract (malloc/free/use in one function, no
calls between free and use). The taint trace records the allocation, the free,
and the use-after-free dereference.

**Arch-aware (x86_64 + AArch64).** The slot-tracking abstraction is identical
across architectures — only the concrete register names, the store/load
mnemonics, the stack-slot operand syntax, and the dereference syntax differ.
This mirrors the sibling intra-procedural CWE-415 double-free check, which
shares the same allocation/free/slot-aliasing machinery:

  * x86_64 (SysV): malloc result in ``rax``; free's first arg in ``rdi``; slot
    store ``mov [rbp-N], rax``; slot reload ``mov reg, [rbp-N]``; register copy
    ``mov dst, src``; dereference through a register base ``[rax]`` /
    ``[rax + 4]`` — all over the ``mov`` family, Intel slots ``[rbp-N]`` /
    ``[rsp-N]``.
  * AArch64 (AAPCS64): malloc result in ``x0``; free's first arg in ``x0``;
    slot store ``str x0, [sp, #N]`` (or ``[x29, #N]``); slot reload
    ``ldr reg, [sp, #N]``; register copy ``mov dst, src``; dereference through a
    register base ``ldr``/``str ..., [x9]`` / ``[x9, #4]``. Capstone renders
    AArch64 64-bit GPRs as ``x0``..``x30`` and the frame/stack registers as
    ``x29``/``sp``.

The per-arch register/mnemonic/regex profile is selected once per run from
``engine.project.arch.name``; the scanning algorithm itself is shared. On an
architecture with no profile the intra-procedural scan is skipped (it would
mis-read register/slot conventions), consistent with how the engine partitions
register-level checks per architecture.

[Worker decision: arch-aware slot profile] Rather than fork the scanner into
two near-identical copies, the architecture-specific surface (return register,
arg register, store/load/copy/deref recognizers) is captured in a small
``_ArchProfile`` and the single ``_scan_function`` body is parameterized by it.
This mirrors the CWE-415 intra-procedural scanner and the engine-level
CWE-190/134/732/369 checks that were made arch-aware the same way.

[Worker decision: register-aware slot tracking] -O0 codegen reloads the stack
slot into a register before each use and copies it into the argument register
before the free call. We therefore track which stack slot the malloc result
lives in, follow reg<-slot reloads, and recognize free's argument even when it
arrives via a register copy. Confidence is ``high`` when the dereferenced
register's alias is rooted in a confirmed reload of the freed stack slot and
``medium`` when the alias was reached only through register-to-register copies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from autopsy.report import Finding, TaintPoint
from autopsy.checks import cwe416_interproc


@dataclass(frozen=True)
class _ArchProfile:
    """Architecture-specific register names and instruction recognizers.

    ``store_ret_to_slot`` matches an instruction storing the allocator's return
    register to a stack slot (groups: base, offset). ``load_slot_to_reg``
    matches a slot reload into a register (groups: dst-reg, base, offset).
    ``reg_copy`` matches a register-to-register move (groups: dst, src).
    ``deref_base`` matches a memory dereference through a register base (group:
    base reg). ``store_mn`` / ``load_mn`` are the mnemonics the store/load
    recognizers apply to. ``arg_reg`` is the first-argument register handed to
    ``free``.
    """

    arg_reg: str
    store_mn: str
    load_mn: str
    store_ret_to_slot: re.Pattern[str]
    load_slot_to_reg: re.Pattern[str]
    reg_copy: re.Pattern[str]
    deref_base: re.Pattern[str]


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
# Memory dereference through a register base: `[rax]`, `[rax + 4]`, etc.
_X86_DEREF = re.compile(r"\[(r[a-z0-9]+)")

_X86_PROFILE = _ArchProfile(
    arg_reg="rdi",
    store_mn="mov",
    load_mn="mov",
    store_ret_to_slot=_X86_STORE,
    load_slot_to_reg=_X86_LOAD,
    reg_copy=_X86_COPY,
    deref_base=_X86_DEREF,
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
# Dereference through a register base: `str wzr, [x9]`, `ldr w0, [x9, #4]`, etc.
# The base register is the first GPR inside the bracketed memory operand. The
# slot/frame registers (sp/x29/fp) are excluded so a stack-slot access (which is
# NOT a dereference of the freed heap pointer) does not look like the use.
_AARCH64_DEREF = re.compile(r"\[(x[0-9]+)(?!\d)")

_AARCH64_PROFILE = _ArchProfile(
    arg_reg="x0",
    store_mn="str",
    load_mn="ldr",
    store_ret_to_slot=_AARCH64_STORE,
    load_slot_to_reg=_AARCH64_LOAD,
    reg_copy=_AARCH64_COPY,
    deref_base=_AARCH64_DEREF,
)

_PROFILES: dict[str, _ArchProfile] = {
    "AMD64": _X86_PROFILE,
    "AARCH64": _AARCH64_PROFILE,
}

# Frame/stack base registers that anchor a stack slot rather than the heap
# pointer; a memory access through one of these is a spill/reload, not the
# use-after-free dereference we are hunting for.
_FRAME_REGS = frozenset({"rbp", "rsp", "sp", "x29", "fp"})


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
    """Run both CWE-416 passes: intra-procedural and single-hop interprocedural.

    The intra-procedural pass (this module) catches free-then-use within one
    function body, on both x86_64 and AArch64. The interprocedural pass
    (:mod:`cwe416_interproc`) catches the single-hop cross-function pattern
    (pointer freed in a callee, used in the caller); it is x86_64-only and
    returns nothing on other architectures. The intra-procedural scan is
    skipped entirely on an architecture with no slot-tracking profile. Findings
    from both are merged; duplicates at the same use address are de-duplicated,
    with the intra-procedural (higher-fidelity) finding taking precedence.
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
    for f in cwe416_interproc.run(engine):
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
    # Registers currently known to alias the freed pointer (slot reloads/copies).
    alias_regs: set[str] = set()
    # Registers whose alias was established by reloading the stack slot directly
    # (confirmed slot aliasing) vs. propagated only through register copies.
    slot_confirmed_regs: set[str] = set()

    for idx, insn in enumerate(insns):
        if _is_call(engine, insn):
            target = _resolve(engine, insn)
            if target in {"malloc", "calloc", "realloc"} and ptr_slot is None:
                malloc_addr = insn.address
                ptr_slot = _slot_after_malloc(insns, idx, prof)
                continue
            if target == "free" and ptr_slot is not None and free_addr is None:
                # Confirm free's arg register aliases our slot.
                if prof.arg_reg in _regs_aliasing_slot(insns, idx, ptr_slot, prof):
                    free_addr = insn.address
                    alias_regs = set()  # reloads after free establish fresh aliases
                    slot_confirmed_regs = set()
                continue
            if free_addr is not None:
                # A call between free and the use breaks the intra-procedural
                # "no calls between free and use" contract; abandon.
                return None
            continue

        if free_addr is None:
            continue

        # --- after the free: hunt for a dereference of the freed pointer ---
        # Track reg <- slot reloads and reg <- reg copies to follow the pointer.
        if insn.mnemonic == prof.load_mn:
            m_load = prof.load_slot_to_reg.match(insn.op_str)
            if m_load:
                base = m_load.group(2)
                off = m_load.group(3) if m_load.lastindex and m_load.lastindex >= 3 else None
                if _slot_key(prof, base, off) == ptr_slot:
                    alias_regs.add(m_load.group(1))
                    slot_confirmed_regs.add(m_load.group(1))
                    continue
        if insn.mnemonic == "mov":
            m_copy = prof.reg_copy.match(insn.op_str)
            if m_copy and m_copy.group(2) in alias_regs:
                alias_regs.add(m_copy.group(1))
                if m_copy.group(2) in slot_confirmed_regs:
                    slot_confirmed_regs.add(m_copy.group(1))
                continue

        # A dereference through an aliasing register is the use-after-free.
        m_deref = prof.deref_base.search(insn.op_str)
        if m_deref:
            base = m_deref.group(1)
            if base not in _FRAME_REGS and base in alias_regs:
                # "high" when the dereferenced register's alias is rooted in a
                # confirmed reload of the freed stack slot; "medium" when it was
                # reached only through register-to-register copies (heuristic).
                confidence = "high" if base in slot_confirmed_regs else "medium"
                return _build_finding(func, malloc_addr, free_addr, insn.address, confidence)

    return None


def _slot_after_malloc(insns, malloc_idx, prof: _ArchProfile):
    """Return the stack-slot key that the malloc result is stored into."""
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


def _build_finding(func, malloc_addr, free_addr, use_addr, confidence="medium"):
    trace = [
        TaintPoint(malloc_addr, "allocation via malloc()"),
        TaintPoint(free_addr, "pointer freed via free()"),
        TaintPoint(use_addr, "freed pointer dereferenced (use-after-free)"),
    ]
    return Finding(
        cwe=416,
        function=func.name,
        address=use_addr,
        evidence=(
            f"freed pointer reused in {func.name} with no intervening call "
            f"(free at {hex(free_addr)}, use at {hex(use_addr)})"
        ),
        taint_trace=trace,
        confidence=confidence,
    )
