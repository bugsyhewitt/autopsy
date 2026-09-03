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

from autopsy.checks import cwe415_interproc
from autopsy.checks._slot_scan import (
    _AARCH64_COPY,
    _AARCH64_LOAD,
    _AARCH64_STORE,
    _X86_COPY,
    _X86_LOAD,
    _X86_STORE,
    _ArchProfile,
    _flatten,
    _is_call,
    _profile_for,
    _regs_aliasing_slot,
    _resolve,
    _slot_after_malloc,
)
from autopsy.report import Finding, TaintPoint

# ---------------------------------------------------------------------------
# CWE-415 arch profiles (no deref_base needed — double-free looks for a
# second free() call, not a pointer dereference).
# ---------------------------------------------------------------------------

_X86_PROFILE = _ArchProfile(
    arg_reg="rdi",
    store_mn="mov",
    load_mn="mov",
    store_ret_to_slot=_X86_STORE,
    load_slot_to_reg=_X86_LOAD,
    reg_copy=_X86_COPY,
)

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
    for f in cwe415_interproc.run(engine):
        if f.address not in intra_addrs:
            findings.append(f)
    return findings


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
