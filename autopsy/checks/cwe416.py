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

from autopsy.report import Finding, TaintPoint
from autopsy.checks import cwe416_interproc
from autopsy.checks._slot_scan import (
    _ArchProfile,
    _X86_STORE,
    _X86_LOAD,
    _X86_COPY,
    _X86_DEREF,
    _AARCH64_STORE,
    _AARCH64_LOAD,
    _AARCH64_COPY,
    _AARCH64_DEREF,
    _profile_for,
    _slot_key,
    _flatten,
    _slot_after_malloc,
    _regs_aliasing_slot,
    _is_call,
    _resolve,
)

# ---------------------------------------------------------------------------
# CWE-416 arch profiles (include deref_base to detect dereferences of the
# freed pointer).
# ---------------------------------------------------------------------------

_X86_PROFILE = _ArchProfile(
    arg_reg="rdi",
    store_mn="mov",
    load_mn="mov",
    store_ret_to_slot=_X86_STORE,
    load_slot_to_reg=_X86_LOAD,
    reg_copy=_X86_COPY,
    deref_base=_X86_DEREF,
)

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
    prof = _profile_for(engine, _PROFILES)
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
        assert prof.deref_base is not None  # always set on CWE-416 profiles
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
