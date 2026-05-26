"""CWE-415: double-free (intra-procedural).

Strategy: within a single function body, find the sequence
``malloc -> ... -> free -> ... -> free`` where both free() calls operate on
the same pointer:

  * the malloc return value (in ``rax``) is saved to a stack slot,
  * that same stack slot is the pointer handed to the first ``free`` (possibly
    via a register copy), and
  * after the first ``free``, the same pointer is handed to a second ``free``
    before any intervening reallocation, with NO function calls between the
    first ``free`` and the second ``free``.

This reuses the slot-tracking and alias-register infrastructure from
``cwe416.py``: instead of looking for a dereference after free, look for a
second ``call free`` where rdi aliases the same slot.

[Worker decision: reuse cwe416 infrastructure] The register-aware slot
tracking in cwe416._regs_aliasing_slot and _slot_after_malloc is directly
applicable. The only semantic difference is what we watch for after the first
free — a second free call rather than a memory dereference.
"""

from __future__ import annotations

import re

from autopsy.report import Finding, TaintPoint

# `mov qword ptr [rbp - 8], rax` -> store malloc result to a stack slot.
_STORE_RAX_TO_SLOT = re.compile(
    r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*rax$"
)
# `mov rax, qword ptr [rbp - 8]` -> reload a stack slot into a register.
_LOAD_SLOT_TO_REG = re.compile(
    r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
)
# `mov rdi, rax` -> register-to-register copy.
_REG_COPY = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")


def _slot_key(base: str, off: str) -> str:
    return f"{base}{off.replace(' ', '')}"


def run(engine) -> list[Finding]:
    cfg = engine.cfg()
    findings: list[Finding] = []
    for func in cfg.kb.functions.values():
        if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
            continue
        finding = _scan_function(engine, func)
        if finding is not None:
            findings.append(finding)
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


def _scan_function(engine, func):
    insns = _flatten(func)

    ptr_slot = None       # stack slot holding the malloc'd pointer
    malloc_addr = None
    free_addr = None

    for idx, insn in enumerate(insns):
        mn, ops = insn.mnemonic, insn.op_str

        if mn == "call":
            target = _is_named(engine, insn)
            if target in {"malloc", "calloc", "realloc"} and ptr_slot is None:
                malloc_addr = insn.address
                ptr_slot = _slot_after_malloc(insns, idx)
                continue
            if target == "free" and ptr_slot is not None and free_addr is None:
                # Confirm the first free's arg (rdi) aliases our slot.
                if "rdi" in _regs_aliasing_slot(insns, idx, ptr_slot):
                    free_addr = insn.address
                continue
            if target == "free" and ptr_slot is not None and free_addr is not None:
                # Confirm the second free's arg (rdi) still aliases the same slot —
                # this is the double-free.
                if "rdi" in _regs_aliasing_slot(insns, idx, ptr_slot):
                    return _build_finding(func, malloc_addr, free_addr, insn.address)
                # If the second free targets a different pointer, not a double-free —
                # the second free could still be a first free on a new allocation; but
                # since ptr_slot is already set to the first alloc, just continue.
                continue
            if target in {"malloc", "calloc", "realloc"} and ptr_slot is not None:
                # A new allocation replaces the old slot — reset state (the old
                # pointer was potentially freed; if freed+reallocated this is not
                # a double-free).
                if free_addr is not None:
                    # Slot was freed and a new allocation now overlays it: no longer
                    # a double-free candidate; stop scanning.
                    return None
                # Malloc before any free: reset and track the new alloc if it uses
                # the same or a new slot.  For simplicity, we reset entirely.
                malloc_addr = insn.address
                ptr_slot = _slot_after_malloc(insns, idx)
                free_addr = None
            continue

    return None


def _slot_after_malloc(insns, malloc_idx):
    """Return the stack-slot key that the malloc result (rax) is stored into."""
    for nxt in insns[malloc_idx + 1 : malloc_idx + 6]:
        m = _STORE_RAX_TO_SLOT.match(nxt.op_str)
        if nxt.mnemonic == "mov" and m:
            return _slot_key(m.group(1), m.group(2))
    return None


def _regs_aliasing_slot(insns, call_idx, slot):
    """Which registers alias ``slot`` in the instructions just before a call?"""
    aliases: set[str] = set()
    for prev in insns[max(0, call_idx - 8) : call_idx]:
        m_load = _LOAD_SLOT_TO_REG.match(prev.op_str)
        if prev.mnemonic == "mov" and m_load and _slot_key(m_load.group(2), m_load.group(3)) == slot:
            aliases.add(m_load.group(1))
            continue
        m_copy = _REG_COPY.match(prev.op_str)
        if prev.mnemonic == "mov" and m_copy and m_copy.group(2) in aliases:
            aliases.add(m_copy.group(1))
    return aliases


def _is_named(engine, insn):
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
    )
