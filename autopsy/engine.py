"""The angr boundary.

Everything that actually touches angr lives here. The module imports angr
lazily (inside :func:`load_project` / :func:`AngrEngine.__init__`) so that
importing ``autopsy.engine`` for type references does not, by itself, pull the
heavy dependency into memory. The fast unit-test layer never instantiates
:class:`AngrEngine`; it mocks this boundary instead.

Design inspiration: BinAbsInspector (Tencent Keenlab) — whole-program flow
analysis for CWE-aligned detection. Engine: angr (SecureSystemsLab).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class StateLimitExceeded(Exception):
    """Raised when symbolic exploration exceeds the configured ``max_states``."""


class EngineError(Exception):
    """Raised when angr fails to load or analyze the target binary."""


@dataclass
class CallSite:
    """A resolved call to an imported function within the target.

    Attributes:
        caller_function: Name of the function containing the call.
        call_address: Address of the call instruction.
        target_name: Name of the called import (e.g. "malloc", "system").
        block_addr: Address of the basic block containing the call.
    """

    caller_function: str
    call_address: int
    target_name: str
    block_addr: int


@dataclass
class MemAccess:
    """A memory store/load with a possibly-symbolic address.

    Attributes:
        function: Containing function name.
        address: Instruction address of the access.
        is_write: True for a store, False for a load.
        symbolic_addr: True if the access address depends on tainted input.
    """

    function: str
    address: int
    is_write: bool
    symbolic_addr: bool


class AngrEngine:
    """Wraps an angr ``Project`` and exposes whole-program analysis helpers.

    The engine is constructed once per binary and shared across checks. It owns
    the CFG and enforces the ``max_states`` cap during any symbolic
    exploration.

    [Worker decision: pragmatic angr usage] angr's full abstract-interpretation
    stack (the original BinAbsInspector approach) is heavy and brittle. For
    v0.1 we drive detection from angr's CFGEmulated/CFGFast call graph plus
    bounded symbolic execution. This satisfies "whole-program flow analysis"
    (reachability + call-graph + taint via symbolic stdin) while staying within
    the token/time budget. Deeper abstract interpretation is a post-v0.1
    direction.
    """

    def __init__(self, binary_path: str, max_states: int = 1000) -> None:
        import angr  # lazy, heavy import
        import logging

        # angr is extremely chatty; silence it for clean JSON output.
        for noisy in ("angr", "cle", "pyvex", "claripy"):
            logging.getLogger(noisy).setLevel(logging.ERROR)

        self.binary_path = binary_path
        self.max_states = max_states
        try:
            # auto_load_libs=False: analyze the target only, not libc.
            self.project = angr.Project(
                binary_path, auto_load_libs=False, load_options={"main_opts": {}}
            )
        except Exception as exc:  # pragma: no cover - exercised in slow tests
            raise EngineError(f"angr failed to load {binary_path!r}: {exc}") from exc

        self._angr = angr
        self._cfg: Any | None = None

    # -- ELF / arch guards ------------------------------------------------

    # Architectures autopsy can load and traverse. x86_64 (AMD64) has full
    # check coverage; AArch64 (ARM64) is supported for the call-site-driven
    # checks only (see ``checks_supported_on_arch`` / the per-arch coverage
    # note below).
    SUPPORTED_ARCHS: tuple[str, ...] = ("AMD64", "AARCH64")

    # CWE checks that run on every architecture in ``SUPPORTED_ARCHS``. Two
    # kinds qualify:
    #
    # (a) Purely call-site-driven checks (call-graph + import symbol
    #     resolution). CWE-78 resolves direct calls by symbol name; CWE-676
    #     (dangerous-function use), CWE-377 (insecure temporary file), CWE-338
    #     (weak-PRNG use) and CWE-367 (TOCTOU check->use) are the same shape —
    #     they pair/flag calls by name and never inspect registers, so they are
    #     sound on AArch64 unchanged.
    #
    # (b) Register-level checks whose register reasoning has been made
    #     arch-aware. CWE-732 (incorrect permission assignment) reads a single
    #     *immediate* mode/mask out of the call's argument register; the engine
    #     helpers know both the SysV/x86_64 and the AArch64 PCS argument
    #     registers and the per-arch immediate-move encoding, so the check is
    #     sound on AArch64 too (see ``chmod_calls_with_permissive_mode`` /
    #     ``umask_calls_with_permissive_mask``). CWE-190 (integer overflow into
    #     an allocator size) inspects the 32-bit size-arithmetic register before
    #     the allocator call; ``size_arith_before_call`` knows both the x86_64
    #     (imul/shl over e**/r**d) and AArch64 (mul/lsl over w0..w30) forms, so
    #     it is sound on AArch64 too. CWE-134 (uncontrolled format string)
    #     inspects the printf-family *format-string* argument register before
    #     the call; ``format_string_sinks_with_nonliteral_format`` knows both
    #     the SysV/x86_64 (``rdi``/``rsi``/``rdx``; literal via ``lea
    #     [rip+disp]``) and the AArch64 (``x0``/``x1``/``x2``; literal via
    #     ``adrp``/``adr``, stack reload via ``ldr``) forms, so it is sound on
    #     AArch64 too.
    #
    #     too. CWE-415 (double-free, intra-procedural) tracks the allocator's
    #     return register into a stack slot and the first-argument register
    #     handed to two successive ``free`` calls; the intra-procedural scanner
    #     in ``checks/cwe415.py`` knows both the x86_64 (``rax``/``rdi``; ``mov``
    #     slot store/reload over ``[rbp-N]``/``[rsp-N]``) and the AArch64
    #     (``x0``; ``str``/``ldr`` over ``[sp,#N]``/``[x29,#N]``) forms, so it is
    #     sound on AArch64 too. (Its single-hop interprocedural companion pass
    #     remains x86_64-only and simply reports nothing on AArch64.)
    #
    #     CWE-369 (divide-by-zero) locates a division whose divisor is not
    #     guarded by a preceding zero-check; ``divisions_with_unguarded_divisor``
    #     knows both the x86_64 (``div``/``idiv`` single divisor operand; guard
    #     via ``cmp``/``test`` + conditional jump) and the AArch64
    #     (``sdiv``/``udiv`` third operand; guard via ``cbz``/``cbnz`` or
    #     ``cmp``/``tst`` + ``b.<cond>``) forms, so it is sound on AArch64 too.
    #     (ARMv8 defines divide-by-zero as 0 rather than a trap, so the AArch64
    #     consequence is a silently-wrong result, not a SIGFPE — but the
    #     unguarded divisor is still the weakness.)
    #
    #     CWE-416 (use-after-free, intra-procedural) reuses the same
    #     allocation/free/stack-slot-aliasing machinery as CWE-415, looking for a
    #     dereference of the freed pointer (rather than a second free) after the
    #     free with no intervening call; ``checks.cwe416`` carries x86_64
    #     (``rax``/``rdi``; ``mov`` over ``[rbp-N]``/``[rsp-N]``; deref ``[rax]``)
    #     and AArch64 (``x0``; ``str``/``ldr`` over ``[sp,#N]``/``[x29,#N]``;
    #     deref ``[x9]``) profiles, so it is sound on AArch64 too. (Its
    #     single-hop interprocedural companion pass remains x86_64-only and
    #     reports nothing on AArch64.)
    #
    #     CWE-119 (buffer over-read/write via an attacker-controlled index)
    #     locates a scaled-index memory access whose register index is derived
    #     from a sign/zero-extended int and that is not guarded by a preceding
    #     bounds-check compare/branch;
    #     ``indexed_memory_access_without_bounds_check`` knows both the x86_64
    #     (scaled-index operand ``[base+index]`` preceded by ``movsxd``/``cdqe``;
    #     guard via ``cmp``) and the AArch64 (``ldrsw``/``sxtw`` index extension,
    #     ``add xD, xBase, xIdx`` base+index sum, deref ``[xD]``; guard via
    #     ``cmp``/``subs``/``tst``/``tbz``/``tbnz``/``cbz``/``cbnz``) forms, so it
    #     is sound on AArch64 too.
    #
    #     CWE-787 (out-of-bounds heap write via malloc + bulk-copy taint
    #     mismatch) co-locates an allocator call and a bulk-copy/fill sink in the
    #     same function, suppressing copies whose *length* argument is a
    #     compile-time immediate; ``copy_call_length_is_literal`` knows both the
    #     SysV/x86_64 (length in ``rdx``; immediate via ``mov edx, #imm``; stack
    #     reload via ``[rbp-N]``/``[rsp-N]``) and the AArch64 (length in ``x2``;
    #     immediate via ``mov w2, #imm`` or the ``wzr`` zero-register form; stack
    #     reload via ``ldr w2, [sp, #N]``/``ldur``) forms, so the check runs on
    #     AArch64 too. The call-site discovery (allocator/source/copy enumeration)
    #     is already arch-agnostic.
    #
    #     CWE-476 (NULL-pointer dereference of an unchecked allocator result)
    #     locates the spill of the allocator's return register to a stack slot,
    #     follows alias propagation through slot reloads and register copies,
    #     and reports the first dereference through an aliasing register that is
    #     not preceded by a NULL-check guard;
    #     ``unchecked_alloc_dereferences`` knows both the SysV/x86_64 (``rax``
    #     return; ``mov [rbp-N], rax`` spill; ``test reg, reg``/``cmp reg, 0`` +
    #     conditional jump guard) and the AArch64 (``x0`` return; ``str x0,
    #     [sp,#N]``/``[x29,#N]`` spill; ``cbz``/``cbnz`` on a slot-aliased
    #     register, or ``cmp xR, #0``/``cmp xR, xzr``/``tst xR, xR`` +
    #     ``b.<cond>`` guard) forms, so it is sound on AArch64 too.
    #
    # All register-level checks are now arch-aware; no check is skipped on
    # AArch64.
    _ARCH_AGNOSTIC_CHECKS: tuple[int, ...] = (78, 119, 134, 190, 338, 367, 369, 377, 415, 416, 476, 676, 732, 787)

    def assert_supported(self) -> None:
        """Reject targets on architectures autopsy cannot analyze.

        x86_64 (AMD64) is fully supported. AArch64 (ARM64) is supported for the
        arch-agnostic checks — the call-site-driven ones (CWE-78/338/367/377/
        676) and the arch-aware register-level checks (CWE-190 integer overflow,
        CWE-732 permission assignment, CWE-134 uncontrolled format string,
        CWE-415 double-free, CWE-416 use-after-free, CWE-369 divide-by-zero,
        CWE-119 buffer over-read/write via an attacker-controlled index,
        CWE-787 heap OOB write via the malloc+bulk-copy co-location heuristic,
        CWE-476 NULL-pointer dereference of an unchecked allocator result).
        All register-level checks are now arch-aware on AArch64 — see
        :meth:`checks_supported_on_arch`.
        """
        arch_name = self.project.arch.name
        if arch_name not in self.SUPPORTED_ARCHS:
            supported = ", ".join(self.SUPPORTED_ARCHS)
            raise EngineError(
                f"unsupported architecture {arch_name!r}; "
                f"autopsy supports: {supported}"
            )

    def checks_supported_on_arch(self, cwes: list[int]) -> tuple[list[int], list[int]]:
        """Partition requested checks into (runnable, skipped) for this arch.

        On x86_64 every check runs. On AArch64 only the architecture-agnostic
        checks in ``_ARCH_AGNOSTIC_CHECKS`` run — the call-site-driven ones plus
        the arch-aware register-level checks (CWE-732/190/134/415/416/369/119/
        787/476). All register-level checks are now arch-aware; nothing is
        skipped on AArch64.

        Args:
            cwes: The CWE ids the caller intends to run.

        Returns:
            ``(runnable, skipped)`` — ordered sublists of ``cwes``. On x86_64
            ``skipped`` is always empty.
        """
        if self.project.arch.name == "AMD64":
            return list(cwes), []
        runnable = [c for c in cwes if c in self._ARCH_AGNOSTIC_CHECKS]
        skipped = [c for c in cwes if c not in self._ARCH_AGNOSTIC_CHECKS]
        return runnable, skipped

    # -- CFG --------------------------------------------------------------

    def cfg(self) -> Any:
        """Build (once) and return a fast CFG of the target."""
        if self._cfg is None:
            try:
                self._cfg = self.project.analyses.CFGFast(normalize=True)
            except Exception as exc:  # pragma: no cover - slow path
                raise EngineError(f"CFG construction failed: {exc}") from exc
        return self._cfg

    def function_containing(self, addr: int) -> str:
        """Best-effort function name for an address; falls back to a hex tag."""
        cfg = self.cfg()
        try:
            func = cfg.kb.functions.floor_func(addr)
            if func is not None:
                return func.name
        except Exception:  # pragma: no cover - defensive
            pass
        return f"sub_{addr:x}"

    # -- Call-site discovery ---------------------------------------------

    # Direct-call mnemonics by architecture. x86_64 uses ``call``; AArch64 uses
    # ``bl`` (branch-with-link). capstone renders both with a hex target operand
    # that :meth:`_resolve_call_target` resolves to a symbol name.
    _CALL_MNEMONICS: dict[str, frozenset[str]] = {
        "AMD64": frozenset({"call"}),
        "AARCH64": frozenset({"bl"}),
    }

    def _call_mnemonics(self) -> frozenset[str]:
        """The direct-call mnemonic set for the target's architecture."""
        return self._CALL_MNEMONICS.get(self.project.arch.name, frozenset({"call"}))

    def call_sites_to(self, names: set[str]) -> list[CallSite]:
        """Find every call to an imported function whose name is in ``names``.

        Walks the CFG call graph and resolves direct-call targets back to their
        symbol names. The direct-call mnemonic is architecture-dependent
        (``call`` on x86_64, ``bl`` on AArch64). Used by the CWE-190 (malloc),
        CWE-78 (system/execve), and CWE-416 (malloc/free) checks.
        """
        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()
        results: list[CallSite] = []
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                try:
                    insns = block.capstone.insns
                except Exception:  # pragma: no cover - defensive
                    continue
                for insn in insns:
                    if insn.mnemonic not in call_mnemonics:
                        continue
                    target_name = self._resolve_call_target(insn, cfg)
                    if target_name in names:
                        results.append(
                            CallSite(
                                caller_function=func.name,
                                call_address=insn.address,
                                target_name=target_name,
                                block_addr=block.addr,
                            )
                        )
        return results

    def in_binary_callees_freeing_arg(self) -> set[str]:
        """Names of in-binary functions that call ``free`` on their argument.

        A function ``F`` is reported when its body contains a ``call free``
        whose pointer argument (``rdi`` on x86_64) aliases ``F``'s first
        incoming parameter — i.e. ``F`` frees a pointer handed to it by its
        caller, rather than a pointer it allocated locally. These are the
        callees that can leave a *caller-held* pointer dangling, which is the
        single-hop cross-function use-after-free pattern (CWE-416) detected by
        the interprocedural check.

        x86_64 only: the parameter/argument alias tracking uses the SysV
        register conventions (first arg in ``rdi``).
        """
        cfg = self.cfg()
        names: set[str] = set()
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            if self._frees_incoming_arg(func, cfg):
                names.add(func.name)
        return names

    def _frees_incoming_arg(self, func: Any, cfg: Any) -> bool:
        """True if ``func`` calls ``free`` on its first incoming parameter.

        On x86_64 the first argument arrives in ``rdi``. -O0 codegen spills it
        to a stack slot in the prologue; before ``call free`` it reloads that
        slot into ``rdi``. We detect a ``call free`` whose ``rdi`` aliases the
        slot that the prologue ``mov [rbp-N], rdi`` stored the parameter into.
        """
        import re

        store_param = re.compile(
            r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*rdi$"
        )
        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")

        insns = []
        for block in func.blocks:
            try:
                insns.extend(block.capstone.insns)
            except Exception:  # pragma: no cover - defensive
                continue
        insns.sort(key=lambda i: i.address)

        param_slot: str | None = None
        for idx, insn in enumerate(insns):
            if insn.mnemonic == "mov":
                m = store_param.match(insn.op_str)
                if m and param_slot is None:
                    param_slot = f"{m.group(1)}{m.group(2).replace(' ', '')}"
                    continue
            if insn.mnemonic == "call" and param_slot is not None:
                target = self._resolve_call_target(insn, cfg)
                if target == "free":
                    # Does rdi alias param_slot at this call?
                    aliases: set[str] = set()
                    for prev in insns[max(0, idx - 8): idx]:
                        ml = load_slot.match(prev.op_str)
                        if prev.mnemonic == "mov" and ml and \
                                f"{ml.group(2)}{ml.group(3).replace(' ', '')}" == param_slot:
                            aliases.add(ml.group(1))
                            continue
                        mc = reg_copy.match(prev.op_str)
                        if prev.mnemonic == "mov" and mc and mc.group(2) in aliases:
                            aliases.add(mc.group(1))
                    if "rdi" in aliases:
                        return True
        return False

    def callers_of(self, name: str) -> list[CallSite]:
        """Every in-binary call site that targets the function ``name``.

        Walks the CFG and resolves direct-call targets, returning a
        :class:`CallSite` for each call to ``name`` from a non-PLT,
        non-simprocedure function. Used by the interprocedural CWE-416 check to
        find the callers of a pointer-freeing helper.
        """
        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()
        results: list[CallSite] = []
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            for block in func.blocks:
                try:
                    insns = block.capstone.insns
                except Exception:  # pragma: no cover - defensive
                    continue
                for insn in insns:
                    if insn.mnemonic not in call_mnemonics:
                        continue
                    if self._resolve_call_target(insn, cfg) == name:
                        results.append(
                            CallSite(
                                caller_function=func.name,
                                call_address=insn.address,
                                target_name=name,
                                block_addr=block.addr,
                            )
                        )
        return results

    def caller_uses_arg_after_call(self, caller_name: str, call_addr: int) -> int | None:
        """Detect a dereference of the call's pointer argument after it returns.

        In caller ``caller_name``, locate the call instruction at
        ``call_addr``. The pointer passed to it lives in ``rdi`` (x86_64 SysV
        first argument), which -O0 codegen sources from a stack slot. After the
        call returns, if that same stack slot is reloaded and dereferenced
        (memory access through the reloaded register) before any other call,
        return the address of that dereference; otherwise ``None``.

        This is the caller-side half of the single-hop cross-function
        use-after-free: the caller hands a pointer to a callee that frees it,
        then uses the now-dangling pointer.

        x86_64 only.
        """
        import re

        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")
        deref_base = re.compile(r"\[(r[a-z0-9]+)")

        cfg = self.cfg()
        func = None
        for f in cfg.kb.functions.values():
            if f.name == caller_name:
                func = f
                break
        if func is None:
            return None

        insns = []
        for block in func.blocks:
            try:
                insns.extend(block.capstone.insns)
            except Exception:  # pragma: no cover - defensive
                continue
        insns.sort(key=lambda i: i.address)

        call_idx = next((i for i, ins in enumerate(insns) if ins.address == call_addr), None)
        if call_idx is None:
            return None

        # Which stack slot supplied rdi to this call (look back a few insns)?
        arg_slot: str | None = None
        rdi_aliases: set[str] = {"rdi"}
        for prev in reversed(insns[max(0, call_idx - 8): call_idx]):
            mc = reg_copy.match(prev.op_str)
            if prev.mnemonic == "mov" and mc and mc.group(1) in rdi_aliases:
                rdi_aliases.add(mc.group(2))
                continue
            ml = load_slot.match(prev.op_str)
            if prev.mnemonic == "mov" and ml and ml.group(1) in rdi_aliases:
                arg_slot = f"{ml.group(2)}{ml.group(3).replace(' ', '')}"
                break
        if arg_slot is None:
            return None

        # After the call: track reloads of arg_slot and look for a dereference,
        # stopping at the next call (which would break the single-hop scope).
        alias_regs: set[str] = set()
        for insn in insns[call_idx + 1:]:
            if insn.mnemonic == "call":
                return None
            ml = load_slot.match(insn.op_str)
            if insn.mnemonic == "mov" and ml and \
                    f"{ml.group(2)}{ml.group(3).replace(' ', '')}" == arg_slot:
                alias_regs.add(ml.group(1))
                continue
            mc = reg_copy.match(insn.op_str)
            if insn.mnemonic == "mov" and mc and mc.group(2) in alias_regs:
                alias_regs.add(mc.group(1))
                continue
            md = deref_base.search(insn.op_str)
            if md and md.group(1) in alias_regs:
                return insn.address
        return None

    def caller_frees_arg_before_call(self, caller_name: str, call_addr: int) -> int | None:
        """Detect that the call's pointer argument was already freed by the caller.

        In caller ``caller_name``, locate the call instruction at ``call_addr``
        (a call to an in-binary helper that frees its argument). The pointer
        passed to it lives in ``rdi`` (x86_64 SysV first argument), which -O0
        codegen sources from a stack slot. If that *same* stack slot was handed
        to ``free`` *earlier in the same function*, with no intervening
        reallocation (``malloc``/``calloc``/``realloc``) that would overwrite
        the slot, return the address of that earlier ``free`` call; otherwise
        ``None``.

        This is the caller-side half of the single-hop cross-function
        double-free (CWE-415): the caller frees a pointer, then passes it to a
        callee that frees it again. It is the symmetric companion to
        :meth:`caller_uses_arg_after_call` (which detects a *dereference* after
        the callee frees, i.e. CWE-416); here the second event is a second
        ``free`` rather than a use.

        x86_64 only: the alias tracking relies on the SysV first-argument
        register (``rdi``) and -O0 stack-slot spill conventions.
        """
        import re

        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        store_to_slot = re.compile(
            r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*(r[a-z0-9]+)$"
        )
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")

        cfg = self.cfg()
        func = None
        for f in cfg.kb.functions.values():
            if f.name == caller_name:
                func = f
                break
        if func is None:
            return None

        insns = []
        for block in func.blocks:
            try:
                insns.extend(block.capstone.insns)
            except Exception:  # pragma: no cover - defensive
                continue
        insns.sort(key=lambda i: i.address)

        call_idx = next((i for i, ins in enumerate(insns) if ins.address == call_addr), None)
        if call_idx is None:
            return None

        # Which stack slot supplied rdi to this (the second-free) call?
        arg_slot: str | None = None
        rdi_aliases: set[str] = {"rdi"}
        for prev in reversed(insns[max(0, call_idx - 8): call_idx]):
            mc = reg_copy.match(prev.op_str)
            if prev.mnemonic == "mov" and mc and mc.group(1) in rdi_aliases:
                rdi_aliases.add(mc.group(2))
                continue
            ml = load_slot.match(prev.op_str)
            if prev.mnemonic == "mov" and ml and ml.group(1) in rdi_aliases:
                arg_slot = f"{ml.group(2)}{ml.group(3).replace(' ', '')}"
                break
        if arg_slot is None:
            return None

        # Scan backward from the call for an earlier `call free` whose rdi
        # aliased the same slot, stopping if the slot is reallocated (a new
        # malloc result stored into it) — that would make the second free a
        # legitimate first free of fresh memory.
        for idx in range(call_idx - 1, -1, -1):
            insn = insns[idx]
            # A store of a register into our slot AFTER an allocation reloads
            # the slot with new memory; treat any `mov [slot], reg` preceded by
            # a malloc-family call as a reallocation that clears the candidate.
            ms = store_to_slot.match(insn.op_str)
            if insn.mnemonic == "mov" and ms and \
                    f"{ms.group(1)}{ms.group(2).replace(' ', '')}" == arg_slot:
                if self._slot_store_follows_alloc(insns, idx, cfg):
                    return None
                continue
            if insn.mnemonic == "call":
                target = self._resolve_call_target(insn, cfg)
                if target == "free":
                    if arg_slot in self._slots_aliasing_rdi_before(insns, idx):
                        return insn.address
                # Any non-free call before our free candidate is irrelevant to
                # whether the slot was freed; keep scanning back.
        return None

    def _slot_store_follows_alloc(self, insns: list, store_idx: int, cfg: Any) -> bool:
        """True if the store at ``store_idx`` writes a malloc-family result.

        Looks back a few instructions for a ``call malloc|calloc|realloc`` whose
        ``rax`` result is what is being stored — i.e. the slot is being
        (re)allocated, not merely re-spilled.
        """
        import re

        reg = re.compile(r"^(?:qword ptr )?\[[^\]]+\],\s*(r[a-z0-9]+)$")
        m = reg.match(insns[store_idx].op_str)
        src = m.group(1) if m else None
        if src is None:
            return False
        for prev in insns[max(0, store_idx - 4): store_idx]:
            if prev.mnemonic == "call":
                if self._resolve_call_target(prev, cfg) in {"malloc", "calloc", "realloc"}:
                    # malloc returns in rax; -O0 stores rax (or its alias) here.
                    return src in {"rax", "eax"}
        return False

    def _slots_aliasing_rdi_before(self, insns: list, call_idx: int) -> set[str]:
        """Stack slots that aliased ``rdi`` in the instructions before a call."""
        import re

        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")

        rdi_aliases: set[str] = {"rdi"}
        slots: set[str] = set()
        for prev in reversed(insns[max(0, call_idx - 8): call_idx]):
            mc = reg_copy.match(prev.op_str)
            if prev.mnemonic == "mov" and mc and mc.group(1) in rdi_aliases:
                rdi_aliases.add(mc.group(2))
                continue
            ml = load_slot.match(prev.op_str)
            if prev.mnemonic == "mov" and ml and ml.group(1) in rdi_aliases:
                slots.add(f"{ml.group(2)}{ml.group(3).replace(' ', '')}")
        return slots

    # printf-family format-string sinks mapped to the SysV/x86_64 register that
    # carries their *format string* argument. The variadic format argument is
    # not always the first parameter: fprintf/sprintf/syslog take it second
    # (after the stream/buffer/priority), snprintf/dprintf third.
    _FORMAT_SINK_FMT_REG: dict[str, str] = {
        "printf": "rdi",          # printf(fmt, ...)
        "vprintf": "rdi",         # vprintf(fmt, va)
        "fprintf": "rsi",         # fprintf(stream, fmt, ...)
        "vfprintf": "rsi",        # vfprintf(stream, fmt, va)
        "sprintf": "rsi",         # sprintf(buf, fmt, ...)
        "vsprintf": "rsi",        # vsprintf(buf, fmt, va)
        "snprintf": "rdx",        # snprintf(buf, size, fmt, ...)
        "vsnprintf": "rdx",       # vsnprintf(buf, size, fmt, va)
        "dprintf": "rsi",         # dprintf(fd, fmt, ...)
        "syslog": "rsi",          # syslog(priority, fmt, ...)
        "vsyslog": "rsi",         # vsyslog(priority, fmt, va)
        "err": "rsi",             # err(eval, fmt, ...)
        "warn": "rdi",            # warn(fmt, ...)
        "errx": "rsi",            # errx(eval, fmt, ...)
        "warnx": "rdi",           # warnx(fmt, ...)
    }

    # The same printf-family sinks mapped to the AArch64 AAPCS64 argument
    # register that carries their *format string*. AAPCS64 passes the first
    # integer/pointer arguments in x0, x1, x2, ...; the format string sits at
    # the same parameter position as on SysV, so the index mapping is identical
    # (printf -> x0, fprintf/sprintf/syslog -> x1, snprintf -> x2). A pointer
    # argument is a full 64-bit value, so the format register is always the
    # x-view (no 32-bit w-view to track, unlike the mode/mask immediates of
    # CWE-732).
    _FORMAT_SINK_FMT_REG_AARCH64: dict[str, str] = {
        "printf": "x0",           # printf(fmt, ...)
        "vprintf": "x0",          # vprintf(fmt, va)
        "fprintf": "x1",          # fprintf(stream, fmt, ...)
        "vfprintf": "x1",         # vfprintf(stream, fmt, va)
        "sprintf": "x1",          # sprintf(buf, fmt, ...)
        "vsprintf": "x1",         # vsprintf(buf, fmt, va)
        "snprintf": "x2",         # snprintf(buf, size, fmt, ...)
        "vsnprintf": "x2",        # vsnprintf(buf, size, fmt, va)
        "dprintf": "x1",          # dprintf(fd, fmt, ...)
        "syslog": "x1",           # syslog(priority, fmt, ...)
        "vsyslog": "x1",          # vsyslog(priority, fmt, va)
        "err": "x1",              # err(eval, fmt, ...)
        "warn": "x0",             # warn(fmt, ...)
        "errx": "x1",             # errx(eval, fmt, ...)
        "warnx": "x0",            # warnx(fmt, ...)
    }

    def _format_sink_fmt_reg_map(self) -> dict[str, str] | None:
        """Per-arch printf-family format-register map, or ``None`` if unsupported."""
        arch = self.project.arch.name
        if arch == "AMD64":
            return self._FORMAT_SINK_FMT_REG
        if arch == "AARCH64":
            return self._FORMAT_SINK_FMT_REG_AARCH64
        return None

    def format_string_sinks_with_nonliteral_format(self) -> list[dict]:
        """Find printf-family calls whose format argument is not a string literal.

        Detects the CWE-134 uncontrolled-format-string pattern: a call to a
        printf-family sink where the *format-string* argument register is
        sourced from a stack slot (a spilled function parameter, or a value
        loaded from the heap / another variable) rather than being set to the
        address of a constant string in ``.rodata``.

        A safe call sets the format register with a ``lea reg, [rip + disp]``
        (PIE/no-PIE rodata pointer) or an immediate address — the format string
        is a compile-time literal and the variadic argument count is fixed.
        The vulnerable call instead reloads the format register from a stack
        slot (``mov reg, [rbp - N]`` / ``[rsp + N]``), which is how -O0 codegen
        materializes an incoming pointer parameter or a heap-loaded buffer.
        ``printf(user_input)`` compiles to exactly this shape.

        Each returned dict describes one sink:
            {
                "function":    caller function name,
                "call_address": address of the call instruction,
                "sink_name":   the printf-family symbol,
                "fmt_reg":     the format-argument register (e.g. "rdi" / "x0"),
                "fmt_slot":    the stack slot the format pointer was loaded from,
            }

        x86_64 (AMD64) and AArch64 (ARM64): the format-argument register mapping
        is per-architecture (SysV ``rdi``/``rsi``/``rdx`` on x86_64; AAPCS64
        ``x0``/``x1``/``x2`` on AArch64), and the slot/aliasing/literal tracking
        recognizes both the x86_64 form (``lea reg, [rip+disp]`` / immediate for
        a rodata literal, ``mov reg, [rbp-N]`` for a stack-slot reload) and the
        AArch64 form (``adrp``/``adr`` for a rodata literal, ``ldr reg, [sp/x29
        +N]`` / ``ldur`` for a stack-slot reload). Returns an empty list on any
        other architecture (the caller check is arch-gated upstream).
        """
        fmt_reg_for_sink = self._format_sink_fmt_reg_map()
        if fmt_reg_for_sink is None:
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        results: list[dict] = []
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in call_mnemonics:
                    continue
                target = self._resolve_call_target(insn, cfg)
                fmt_reg = fmt_reg_for_sink.get(target)
                if fmt_reg is None:
                    continue

                fmt_slot = self._resolve_format_arg_slot(insns, idx, fmt_reg)
                if fmt_slot is None:
                    # Either a confirmed string literal, or we could not prove
                    # the format came from a stack slot — stay conservative and
                    # do not flag (zero-false-positive guarantee).
                    continue

                results.append(
                    {
                        "function": func.name,
                        "call_address": insn.address,
                        "sink_name": target,
                        "fmt_reg": fmt_reg,
                        "fmt_slot": fmt_slot,
                    }
                )
        return results

    def _resolve_format_arg_slot(
        self, insns: list[Any], call_idx: int, fmt_reg: str
    ) -> str | None:
        """Resolve a printf-family format-arg register to its source stack slot.

        Walks back from the call at ``insns[call_idx]`` to determine how
        ``fmt_reg`` was last set, following register-copy aliases. Returns the
        stack-slot name the format pointer was reloaded from (the non-literal /
        possibly attacker-controlled case) or ``None`` if the format is a
        compile-time string literal (set from a rodata pointer / immediate
        address) or the source could not be resolved — the conservative outcome
        that preserves the zero-false-positive posture.

        Architecture-aware. On x86_64 a literal is ``lea reg, [rip+disp]`` (or an
        immediate move) and a non-literal is ``mov reg, [rbp-N]``/``[rsp+N]``. On
        AArch64 a literal materializes the rodata pointer with ``adrp``/``adr``
        and a non-literal reloads from a stack slot with ``ldr reg, [sp/x29
        +N]``/``ldur``.
        """
        import re

        if self.project.arch.name == "AARCH64":
            # AArch64 (AAPCS64). A pointer argument is a full 64-bit value, so
            # the format register and its aliases are tracked in the x-view.
            base = fmt_reg[1:]  # "x0" -> "0"
            fmt_aliases: set[str] = {f"x{base}", f"w{base}"}
            # reg <- [sp/x29 +/- N]: a stack-slot reload (non-literal format).
            load_slot = re.compile(
                r"^([wx][0-9a-z]+),\s*\[(sp|x29|fp)(?:,\s*#([+\-]?(?:0x[0-9a-f]+|\d+)))?\]"
            )
            # reg <- reg: a register copy (alias propagation).
            reg_copy = re.compile(r"^([wx][0-9a-z]+),\s*([wx][0-9a-z]+)$")
            # The stack-slot load mnemonics -O0 uses to reload a spilled pointer.
            load_like = {"ldr", "ldur"}
            for prev in reversed(insns[max(0, call_idx - 14): call_idx]):
                mnem = prev.mnemonic
                if mnem in ("adrp", "adr"):
                    # A rodata pointer materialization -> compile-time literal.
                    md = re.match(r"^([wx][0-9a-z]+),", prev.op_str)
                    if md and self._aarch64_reg_in(md.group(1), fmt_aliases):
                        return None
                    continue
                if mnem in load_like:
                    ms = load_slot.match(prev.op_str)
                    if ms and self._aarch64_reg_in(ms.group(1), fmt_aliases):
                        disp = ms.group(3)
                        slot = f"{ms.group(2)}{('+' + disp) if disp and not disp.startswith(('+', '-')) else (disp or '')}"
                        return slot
                    continue
                if mnem in ("mov", "orr"):
                    mc = reg_copy.match(prev.op_str)
                    if mc and self._aarch64_reg_in(mc.group(1), fmt_aliases):
                        src = mc.group(2)
                        fmt_aliases = fmt_aliases | {src, "x" + src[1:], "w" + src[1:]}
                        continue
            return None

        # x86_64 (SysV). Track the format register and its aliases; a literal is
        # set via `lea reg, [rip+disp]` or an immediate, a non-literal reloads a
        # stack slot.
        fmt_aliases = {fmt_reg}
        # reg <- [rbp/rsp +/- N]: a stack-slot reload (non-literal format).
        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        # reg <- reg: a register copy (alias propagation).
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")
        # reg <- [rip + disp] (lea) or an immediate: a constant rodata pointer.
        lea_rip = re.compile(r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[rip\s*[+\-]")
        mov_imm = re.compile(r"^(r[a-z0-9]+),\s*(?:0x[0-9a-f]+|\d+)$")
        for prev in reversed(insns[max(0, call_idx - 12): call_idx]):
            if prev.mnemonic == "lea":
                ml = lea_rip.match(prev.op_str)
                if ml and ml.group(1) in fmt_aliases:
                    return None  # confirmed string literal
            if prev.mnemonic == "mov":
                # lea-style not used, but a direct immediate address.
                mi = mov_imm.match(prev.op_str)
                if mi and mi.group(1) in fmt_aliases:
                    return None  # confirmed string literal
                ms = load_slot.match(prev.op_str)
                if ms and ms.group(1) in fmt_aliases:
                    return f"{ms.group(2)}{ms.group(3).replace(' ', '')}"
                mc = reg_copy.match(prev.op_str)
                if mc and mc.group(1) in fmt_aliases:
                    # dest aliases the format reg; its source now does too.
                    fmt_aliases.add(mc.group(2))
                    continue
        return None

    # Bulk-copy/fill sinks mapped to the SysV/x86_64 register that carries their
    # *length* (byte-count) argument. ``strcpy`` is deliberately absent: it takes
    # no explicit length (it copies until a NUL), so its write extent is never a
    # compile-time literal and it is always treated as a potential overflow sink.
    _COPY_SINK_LEN_REG: dict[str, str] = {
        "memcpy": "rdx",    # memcpy(dst, src, n)
        "memmove": "rdx",   # memmove(dst, src, n)
        "memset": "rdx",    # memset(dst, c, n)
        "strncpy": "rdx",   # strncpy(dst, src, n)
        "strncat": "rdx",   # strncat(dst, src, n)
        "bcopy": "rdx",     # bcopy(src, dst, n)
    }

    # The same mapping for AArch64. AAPCS64 passes integer arguments in
    # ``x0..x7`` (32-bit views ``w0..w7``); the *length* argument is the third
    # parameter on every sink (``memcpy(dst, src, n)`` etc.), so it arrives in
    # ``x2``. A small literal length is materialized into the 32-bit ``w2``
    # view at -O0 (zero-extending into ``x2``); the 64-bit name is recorded
    # so register-copy aliasing through either view is followed.
    _COPY_SINK_LEN_REG_AARCH64: dict[str, str] = {
        "memcpy": "x2",     # memcpy(dst, src, n)
        "memmove": "x2",    # memmove(dst, src, n)
        "memset": "x2",     # memset(dst, c, n)
        "strncpy": "x2",    # strncpy(dst, src, n)
        "strncat": "x2",    # strncat(dst, src, n)
        "bcopy": "x2",      # bcopy(src, dst, n)
    }

    def copy_call_length_is_literal(
        self, caller_function: str, call_address: int, sink_name: str
    ) -> bool:
        """True if a bulk-copy sink's *length* argument is a compile-time literal.

        For a copy/fill call (``memcpy``/``memmove``/``memset``/``strncpy``/
        ``strncat``/``bcopy``) in ``caller_function`` at ``call_address``, walk
        back from the call and resolve how the length-argument register (``rdx``
        on x86_64 SysV) was last set. If it was set by an immediate move
        (``mov rdx, 0x3f``) the copy length is a fixed compile-time constant and
        therefore *cannot* be attacker-controlled — such a call cannot produce a
        tainted out-of-bounds heap write, so the CWE-787 co-location heuristic
        must not flag on it.

        Returns ``True`` only when the length is provably an immediate. If the
        length comes from a stack slot, a register, or cannot be resolved, the
        method returns ``False`` (conservative: treat as possibly-tainted).
        ``strcpy`` (no length argument) always returns ``False``.

        x86_64 (AMD64) and AArch64 (ARM64). On AArch64 the length-argument
        register is ``x2`` (AAPCS64) and the immediate-move encoding is
        ``mov w2, #imm`` (with ``mov w2, wzr`` encoding a literal ``0``); a
        runtime length reloads from a stack slot (``ldr w2, [sp, #N]`` /
        ``ldur``). On any other architecture this returns ``False`` (the
        heuristic stays conservative).
        """
        import re

        arch = self.project.arch.name
        if arch == "AARCH64":
            len_reg = self._COPY_SINK_LEN_REG_AARCH64.get(sink_name)
            if len_reg is None:
                return False
            # Reuse the arch-aware immediate resolver. A length resolved to *any*
            # compile-time immediate (including 0) is a literal — the value does
            # not matter for the CWE-787 suppression, only that it cannot be
            # attacker-controlled.
            cfg = self.cfg()
            func = None
            for f in cfg.kb.functions.values():
                if f.name == caller_function:
                    func = f
                    break
            if func is None:
                return False
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)
            call_idx = next(
                (i for i, ins in enumerate(insns) if ins.address == call_address),
                None,
            )
            if call_idx is None:
                return False
            return self._resolve_arg_immediate(insns, call_idx, len_reg) is not None
        if arch != "AMD64":
            return False
        len_reg = self._COPY_SINK_LEN_REG.get(sink_name)
        if len_reg is None:
            return False

        # 32-bit sub-register alias: edx writes zero-extend into rdx, and -O0
        # codegen materializes a small literal length as `mov edx, 0x3f`.
        len_aliases = {len_reg, "e" + len_reg[1:]}

        # reg <- immediate: a compile-time constant length.
        mov_imm = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(?:0x[0-9a-f]+|\d+)$")
        # reg <- reg: a register copy (alias propagation).
        reg_copy = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(r[a-z0-9]+|e[a-z0-9]+)$")
        # reg <- [rbp/rsp +/- N]: a stack-slot reload (non-literal / possibly tainted).
        load_slot = re.compile(
            r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(?:[a-z]+ ptr )?\[(rbp|rsp)\s*[+\-]"
        )

        cfg = self.cfg()
        func = None
        for f in cfg.kb.functions.values():
            if f.name == caller_function:
                func = f
                break
        if func is None:
            return False

        insns: list[Any] = []
        for block in func.blocks:
            try:
                insns.extend(block.capstone.insns)
            except Exception:  # pragma: no cover - defensive
                continue
        insns.sort(key=lambda i: i.address)

        call_idx = next(
            (i for i, ins in enumerate(insns) if ins.address == call_address), None
        )
        if call_idx is None:
            return False

        # mov-family mnemonics that move a value into a register: plain mov plus
        # the sign/zero-extending forms -O0 uses to widen a small length
        # (`movsxd rdx, eax`, `movzx`, `movsx`).
        mov_like = {"mov", "movsxd", "movsx", "movzx"}

        # Walk back resolving how the length register was last set, following
        # register-copy aliases (e.g. `movsxd rdx, eax; mov eax, 0x10`).
        for prev in reversed(insns[max(0, call_idx - 12): call_idx]):
            if prev.mnemonic not in mov_like:
                continue
            mi = mov_imm.match(prev.op_str)
            if mi and self._reg_in(mi.group(1), len_aliases):
                return True  # length set from an immediate -> literal
            ms = load_slot.match(prev.op_str)
            if ms and self._reg_in(ms.group(1), len_aliases):
                return False  # length reloaded from a stack slot -> possibly tainted
            mc = reg_copy.match(prev.op_str)
            if mc and self._reg_in(mc.group(1), len_aliases):
                # dest aliases the length reg; follow its source instead.
                len_aliases = len_aliases | {mc.group(2), self._widen(mc.group(2))}
                continue
        return False

    # Permission-setting sinks mapped to the SysV/x86_64 register that carries
    # their *mode* argument (the octal permission bits). ``chmod``/``fchmod``/
    # ``lchmod`` take the mode as their second parameter (``rsi``); ``fchmodat``
    # takes it third (``rsi`` is the path, ``rdx`` the mode). ``umask`` takes its
    # single mask argument first (``rdi``) — it is handled separately because the
    # *dangerous* mask is the inverse pattern (a mask that does NOT mask off the
    # group/other write bits).
    _CHMOD_SINK_MODE_REG: dict[str, str] = {
        "chmod": "rsi",       # chmod(path, mode)
        "fchmod": "rsi",      # fchmod(fd, mode)
        "lchmod": "rsi",      # lchmod(path, mode)
        "fchmodat": "rdx",    # fchmodat(dirfd, path, mode, flags)
    }

    # The same mapping for AArch64. The AAPCS64 procedure call standard passes
    # integer arguments in x0..x7 (32-bit views w0..w7): chmod's mode is the
    # second argument (x1/w1), fchmodat's mode the third (x2/w2). A mode literal
    # is a small octal value that -O0 codegen materializes with a 32-bit move
    # into the w-view, so the mode arrives in w1 / w2 (which zero-extends into
    # x1 / x2). The 64-bit x-name is recorded so register-copy aliasing through
    # either view is followed.
    _CHMOD_SINK_MODE_REG_AARCH64: dict[str, str] = {
        "chmod": "x1",        # chmod(path, mode)
        "fchmod": "x1",       # fchmod(fd, mode)
        "lchmod": "x1",       # lchmod(path, mode)
        "fchmodat": "x2",     # fchmodat(dirfd, path, mode, flags)
    }

    # The world-write (0o002) and group-write (0o020) permission bits. A mode
    # that sets either grants write access beyond the owner — the CWE-732
    # "incorrect permission assignment for a critical resource" signal.
    _WORLD_WRITE = 0o002
    _GROUP_WRITE = 0o020

    def chmod_calls_with_permissive_mode(self) -> list[dict[str, Any]]:
        """Find chmod-family calls whose *mode* immediate grants group/other write.

        Detects the CWE-732 (Incorrect Permission Assignment for Critical
        Resource) pattern: a call to ``chmod``/``fchmod``/``lchmod``/``fchmodat``
        whose permission-mode argument is a compile-time immediate that sets the
        group-write (``0o020``) or world-write (``0o002``) bit — e.g.
        ``chmod(path, 0777)`` or ``chmod(path, 0666)``. Such a mode makes the
        resource writable by users other than the owner, which is the classic
        permission-assignment weakness.

        The mode argument register is architecture- and function-specific (SysV:
        ``rsi`` for chmod/fchmod/lchmod, ``rdx`` for fchmodat). This method walks
        back from each call resolving how that register was last set; it reports
        the site only when the mode is provably an immediate with a group/other
        write bit set. Modes loaded from a register or stack slot (computed at
        runtime) are NOT flagged — the value is unknown, so flagging would risk a
        false positive and break autopsy's zero-false-positive posture.

        Returns one dict per permissive-mode call:
        ``{"address": int, "function": str, "sink_name": str, "mode": int}``.

        x86_64 (AMD64) and AArch64 (ARM64): the mode-argument register mapping is
        per-architecture (SysV ``rsi``/``rdx`` on x86_64; AAPCS64 ``x1``/``x2``
        on AArch64) and the immediate/aliasing tracking handles both the x86_64
        ``mov esi, 0x1ff`` form and the AArch64 ``mov w1, #0x1ff`` form. Returns
        an empty list on any other architecture.
        """
        mode_reg_for_sink = self._chmod_mode_reg_map()
        if mode_reg_for_sink is None:
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        results: list[dict[str, Any]] = []
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in call_mnemonics:
                    continue
                target = self._resolve_call_target(insn, cfg)
                mode_reg = mode_reg_for_sink.get(target)
                if mode_reg is None:
                    continue

                mode_val = self._resolve_arg_immediate(insns, idx, mode_reg)
                if mode_val is None:
                    continue
                if mode_val & (self._WORLD_WRITE | self._GROUP_WRITE):
                    results.append(
                        {
                            "address": insn.address,
                            "function": func.name,
                            "sink_name": target,
                            "mode": mode_val,
                        }
                    )
        return results

    def _chmod_mode_reg_map(self) -> dict[str, str] | None:
        """Per-arch chmod-family mode-register map, or ``None`` if unsupported."""
        arch = self.project.arch.name
        if arch == "AMD64":
            return self._CHMOD_SINK_MODE_REG
        if arch == "AARCH64":
            return self._CHMOD_SINK_MODE_REG_AARCH64
        return None

    def _resolve_arg_immediate(
        self, insns: list[Any], call_idx: int, arg_reg: str
    ) -> int | None:
        """Resolve a call argument register to a compile-time immediate value.

        Walks back from the call at ``insns[call_idx]`` to determine how
        ``arg_reg`` was last set, following register-copy aliases. Returns the
        integer value if it was set from an immediate move, or ``None`` if the
        value was loaded from memory (runtime-computed) or could not be resolved
        — the conservative outcome that preserves the zero-false-positive
        posture.

        Architecture-aware. On x86_64 the immediate form is ``mov esi, 0x1ff``
        and a runtime value reloads a stack slot (``mov esi, [rbp - N]``). On
        AArch64 the immediate form is ``mov w1, #0x1ff`` (and ``mov w0, wzr`` —
        the zero register — encodes a literal ``0``, e.g. ``umask(0)``), while a
        runtime value loads from memory (``ldr w1, [sp, #N]`` / ``ldur``).
        """
        import re

        if self.project.arch.name == "AARCH64":
            # AArch64 (AAPCS64). Mode literals are materialized into the 32-bit
            # w-view (which zero-extends into the x register); track both views.
            base = arg_reg[1:]  # "x1" -> "1"
            aliases = {f"x{base}", f"w{base}"}
            # reg <- #imm: `mov w1, #0x1ff` / `mov w1, #511`.
            mov_imm = re.compile(r"^([wx][0-9a-z]+),\s*#((?:0x[0-9a-f]+)|\d+)$")
            # reg <- wzr/xzr: the zero register encodes a literal 0 (umask(0)).
            mov_zr = re.compile(r"^([wx][0-9a-z]+),\s*([wx]zr)$")
            # reg <- reg: a register copy (alias propagation).
            reg_copy = re.compile(r"^([wx][0-9a-z]+),\s*([wx][0-9a-z]+)$")
            # reg <- [mem]: a load from a stack slot/memory (runtime value).
            load_mem = re.compile(r"^([wx][0-9a-z]+),\s*\[")
            mov_like = {"mov", "movz", "ldr", "ldur"}
            for prev in reversed(insns[max(0, call_idx - 12): call_idx]):
                if prev.mnemonic not in mov_like:
                    continue
                mi = mov_imm.match(prev.op_str)
                if mi and self._aarch64_reg_in(mi.group(1), aliases):
                    return int(mi.group(2), 0)
                mz = mov_zr.match(prev.op_str)
                if mz and self._aarch64_reg_in(mz.group(1), aliases):
                    return 0
                ml = load_mem.match(prev.op_str)
                if ml and self._aarch64_reg_in(ml.group(1), aliases):
                    # mode reloaded from memory -> runtime value, unknown.
                    return None
                mc = reg_copy.match(prev.op_str)
                if mc and self._aarch64_reg_in(mc.group(1), aliases):
                    src = mc.group(2)
                    aliases = aliases | {src, "x" + src[1:], "w" + src[1:]}
                    continue
            return None

        # x86_64 (SysV). The 32-bit sub-register (esi/edx/edi) zero-extends into
        # the 64-bit arg register; -O0 sets a small octal literal via that form.
        aliases = {arg_reg, "e" + arg_reg[1:]}
        mov_imm = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*((?:0x[0-9a-f]+)|\d+)$")
        reg_copy = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(r[a-z0-9]+|e[a-z0-9]+)$")
        load_slot = re.compile(
            r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(?:[a-z]+ ptr )?\[(rbp|rsp)\s*[+\-]"
        )
        for prev in reversed(insns[max(0, call_idx - 12): call_idx]):
            if prev.mnemonic != "mov":
                # Non-mov touching the arg reg would mean a computed value we
                # can't resolve; stay conservative and stop scanning it.
                continue
            mi = mov_imm.match(prev.op_str)
            if mi and self._reg_in(mi.group(1), aliases):
                return int(mi.group(2), 0)
            ms = load_slot.match(prev.op_str)
            if ms and self._reg_in(ms.group(1), aliases):
                # arg reloaded from a stack slot -> runtime value, unknown.
                return None
            mc = reg_copy.match(prev.op_str)
            if mc and self._reg_in(mc.group(1), aliases):
                aliases = aliases | {mc.group(2), self._widen(mc.group(2))}
                continue
        return None

    @staticmethod
    def _aarch64_reg_in(reg: str, aliases: set[str]) -> bool:
        """True if an AArch64 register (either w/x view) is in the alias set.

        Treats the 32-bit ``wN`` and 64-bit ``xN`` views as the same register —
        ``mov w1, #0x1ff`` sets the same logical argument as ``x1``.
        """
        if reg in aliases:
            return True
        if len(reg) >= 2 and reg[0] in ("w", "x"):
            num = reg[1:]
            return f"x{num}" in aliases or f"w{num}" in aliases
        return False

    # -- CWE-190 size-arithmetic discovery (arch-aware) -------------------

    # Overflow-prone arithmetic mnemonics by architecture. On x86_64 a size is
    # computed with imul/mul/add/shl/sal or an lea-with-scale; on AArch64 the
    # same shapes are mul/madd/add and lsl (shift-left == multiply by a power of
    # two). All operate here on the 32-bit register view, which truncates and so
    # is the integer-overflow surface CWE-190 looks for.
    _SIZE_ARITH_MNEMONICS: dict[str, frozenset[str]] = {
        "AMD64": frozenset({"imul", "mul", "add", "shl", "sal", "lea"}),
        "AARCH64": frozenset({"mul", "madd", "add", "lsl"}),
    }

    # 32-bit register tokens whose arithmetic results truncate to 32 bits — the
    # overflow surface. x86_64: the e** / r**d views. AArch64: the w0..w30 view
    # (a w-write zero-extends into the x register, dropping the high 32 bits).
    _SIZE_ARITH_E_REGS: tuple[str, ...] = (
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    )

    def size_arith_before_call(self, call: "CallSite") -> tuple[int, str, bool] | None:
        """Find the last overflow-prone 32-bit size arithmetic before ``call``.

        Scans the basic blocks of the function containing the allocator call
        ``call`` for the last arithmetic instruction that computes a value in a
        32-bit register (the truncation/overflow surface) before the call. This
        is the engine half of the CWE-190 (integer-overflow-into-allocator-size)
        heuristic — :mod:`autopsy.checks.cwe190` pairs it with an attacker-input
        source to flag a tainted, potentially-overflowing allocation size.

        Returns ``(address, mnemonic, two_reg_operands)`` for that arithmetic op,
        or ``None`` if no overflow-prone arithmetic precedes the call.
        ``two_reg_operands`` is True when the op combines two distinct register
        *source* operands (both potentially tainted, data-dependent values that
        can overflow together) rather than a register/immediate pair; the check
        maps that to "high" vs "medium" confidence.

        Architecture-aware. On x86_64 the arithmetic is imul/mul/add/shl/sal/lea
        over the e**/r**d register views (e.g. ``imul eax, ecx`` / ``shl eax,
        0x2``). On AArch64 it is mul/madd/add/lsl over the w0..w30 view (e.g.
        ``mul w8, w8, w9`` — two registers, high — or ``lsl w8, w8, #0xc`` — a
        register and an immediate shift, medium). Returns ``None`` on any other
        architecture.
        """
        import re

        arch = self.project.arch.name
        mnemonics = self._SIZE_ARITH_MNEMONICS.get(arch)
        if mnemonics is None:
            return None

        cfg = self.cfg()
        func = cfg.kb.functions.get(call.caller_function)
        if func is None:
            try:
                func = cfg.kb.functions.floor_func(call.call_address)
            except Exception:  # pragma: no cover - defensive
                func = None
        if func is None:
            return None

        if arch == "AARCH64":
            # w0..w30 (and the zero register wzr, which never carries a size).
            reg_re = re.compile(r"\bw(?:[12]?[0-9]|30)\b")
        else:
            reg_re = re.compile(
                r"\b(?:eax|ebx|ecx|edx|esi|edi|ebp|esp|"
                r"r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d)\b"
            )

        candidate: tuple[int, str, bool] | None = None
        for block in func.blocks:
            try:
                insns = block.capstone.insns
            except Exception:  # pragma: no cover - defensive
                continue
            for insn in insns:
                if insn.address >= call.call_address:
                    continue
                if insn.mnemonic not in mnemonics:
                    continue
                if not reg_re.search(insn.op_str):
                    continue
                two_reg = self._size_arith_two_source_regs(
                    arch, insn.op_str, reg_re
                )
                candidate = (insn.address, insn.mnemonic, two_reg)
        return candidate

    @staticmethod
    def _size_arith_two_source_regs(arch: str, op_str: str, reg_re) -> bool:
        """True if a size-arithmetic op combines two distinct register sources.

        The destination register is excluded so a self-referential op such as
        ``shl eax, 0x2`` / ``lsl w8, w8, #0xc`` (one logical source plus an
        immediate) is counted as a single register operand (-> medium), while
        ``imul eax, ecx`` / ``mul w8, w8, w9`` (two distinct data-dependent
        sources) counts as two (-> high). On AArch64 the first operand is always
        the destination; on x86_64 the first operand is both source and
        destination, so it is still a source and is retained.
        """
        operands = [o.strip() for o in op_str.split(",")]
        regs = [reg_re.search(o).group(0) for o in operands if reg_re.search(o)]
        if not regs:
            return False
        if arch == "AARCH64":
            # `mnemonic dst, src1, src2` — drop the destination, count the rest.
            sources = regs[1:]
        else:
            # x86_64 `mnemonic dst/src1, src2` — the destination is also a
            # source operand, so every register token is a source.
            sources = regs
        return len(set(sources)) >= 2

    def umask_calls_with_permissive_mask(self) -> list[dict[str, Any]]:
        """Find ``umask`` calls whose immediate mask fails to mask group/other write.

        ``umask(mask)`` sets the process file-creation mask: bits set in ``mask``
        are *removed* from the default permissions of newly-created files. A
        secure program sets ``umask(0o077)`` (strip all group/other access) or at
        least ``umask(0o022)`` (strip group/other write). ``umask(0)`` — or any
        mask that leaves the group-write (``0o020``) or world-write (``0o002``)
        bit clear — means subsequently-created files can be group/world writable,
        the CWE-732 weakness applied to the whole process.

        This flags a ``umask`` call whose mask is a compile-time immediate that
        does NOT set both the group-write and world-write bits (i.e.
        ``(mask & 0o022) != 0o022``). The argument lives in ``rdi`` (SysV first
        argument). Runtime-computed masks are not flagged (unknown value).

        Returns one dict per permissive-mask call:
        ``{"address": int, "function": str, "sink_name": "umask", "mode": int}``.

        x86_64 (AMD64) and AArch64 (ARM64): the mask argument is the first
        parameter (SysV ``rdi`` / AAPCS64 ``x0``) and the immediate is resolved
        per-architecture — including the AArch64 ``mov w0, wzr`` zero-register
        form that encodes ``umask(0)``. Returns an empty list on any other
        architecture.
        """
        # First-argument register holding the mask: SysV rdi / AAPCS64 x0.
        arch = self.project.arch.name
        if arch == "AMD64":
            mask_reg = "rdi"
        elif arch == "AARCH64":
            mask_reg = "x0"
        else:
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        results: list[dict[str, Any]] = []
        strip_bits = self._WORLD_WRITE | self._GROUP_WRITE  # 0o022
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in call_mnemonics:
                    continue
                if self._resolve_call_target(insn, cfg) != "umask":
                    continue
                mask_val = self._resolve_arg_immediate(insns, idx, mask_reg)
                if mask_val is None:
                    continue
                # Dangerous when the mask does not strip BOTH group- and
                # world-write bits — i.e. files it creates can be made writable
                # by group/other.
                if (mask_val & strip_bits) != strip_bits:
                    results.append(
                        {
                            "address": insn.address,
                            "function": func.name,
                            "sink_name": "umask",
                            "mode": mask_val,
                        }
                    )
        return results

    # Division mnemonics whose divisor can be zero at runtime, by architecture.
    # x86_64 ``div``/``idiv`` take the divisor as their single explicit operand
    # and raise #DE (SIGFPE) when it is 0. AArch64 ``sdiv``/``udiv`` take the
    # divisor as the *third* operand (``sdiv Wd, Wn, Wm`` -> Wm); ARMv8 does not
    # trap on integer divide-by-zero — the result is defined as 0 — so the
    # weakness on AArch64 is the logic error (a silently-wrong 0 result that an
    # attacker can force), not a crash. Either way the unguarded divisor is the
    # CWE-369 site the check reports.
    _DIV_MNEMONICS: frozenset[str] = frozenset({"div", "idiv"})
    _DIV_MNEMONICS_AARCH64: frozenset[str] = frozenset({"sdiv", "udiv"})

    def divisions_with_unguarded_divisor(self) -> list[dict[str, Any]]:
        """Find division sites whose divisor is a non-immediate, unguarded value.

        A division is a candidate CWE-369 site unless the program *guards* the
        divisor with a zero-check before the divide. For each division this
        method walks back through the instructions that precede it in the same
        function and looks for a guard naming the divisor register (or its
        widening); guarded sites are excluded to preserve the zero-false-positive
        guarantee on well-written code (``if (d == 0) return;``).

        Architecture-aware. On x86_64 ``div``/``idiv`` take a single explicit
        operand — the divisor — which is always a register or memory location
        (no immediate form); the CPU raises a divide-error (#DE → SIGFPE) when
        that divisor is zero. The guard idiom is a ``test``/``cmp`` naming the
        divisor followed by a conditional jump (``je``/``jz``/...). On AArch64
        ``sdiv``/``udiv`` take the divisor as the *third* operand
        (``sdiv Wd, Wn, Wm`` → ``Wm``); the guard idiom is a ``cbz``/``cbnz`` on
        the divisor, or a ``cmp``/``tst`` naming it followed by a conditional
        branch (``b.eq``/``b.ne``/...). (ARMv8 defines divide-by-zero as 0 rather
        than a trap, so the AArch64 consequence is a silently-wrong result an
        attacker can force, not a SIGFPE — but the unguarded divisor is still the
        weakness.)

        Returns one dict per *unguarded* division:
        ``{"address": int, "function": str, "divisor": str}``. The list is empty
        on architectures other than AMD64/AARCH64.
        """
        import re

        arch = self.project.arch.name
        if arch == "AMD64":
            div_mnemonics = self._DIV_MNEMONICS
            aarch64 = False
        elif arch == "AARCH64":
            div_mnemonics = self._DIV_MNEMONICS_AARCH64
            aarch64 = True
        else:
            return []

        # The divisor operand of div/idiv (x86_64): a bare register (``rcx``/
        # ``ecx``) or a memory reference (``dword ptr [rbp-4]``).
        reg_operand = re.compile(r"^(?:[a-z]+ ptr )?(?:[er][a-z0-9]+|[a-z]+l|[a-z]+x)$")
        # An AArch64 GPR token (the w/x view), used to pull the divisor (third
        # operand of sdiv/udiv) and to match a guard register.
        aarch64_reg = re.compile(r"\b([wx](?:[12]?[0-9]|3[01]|zr))\b")
        # x86_64 zero-check guard: cmp/test naming the divisor, then a cond. jump.
        cond_jumps = {
            "je", "jz", "jne", "jnz", "jbe", "jb", "ja", "jae",
            "jle", "jl", "jg", "jge", "js", "jns",
        }
        # AArch64 conditional-branch suffixes following a cmp/tst guard.
        aarch64_cond_branches = {
            "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
            "b.hi", "b.hs", "b.lo", "b.ls", "b.mi", "b.pl",
        }

        cfg = self.cfg()
        results: list[dict[str, Any]] = []
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in div_mnemonics:
                    continue

                if aarch64:
                    # sdiv/udiv Wd, Wn, Wm -> the divisor is the third operand.
                    operands = [o.strip() for o in insn.op_str.split(",")]
                    if len(operands) < 3:
                        continue
                    m = aarch64_reg.search(operands[2])
                    if not m:
                        continue
                    divisor = m.group(1)
                    num = divisor[1:]
                    aliases = {f"w{num}", f"x{num}"}
                    # At -O0 the divisor register is reloaded from a stack slot
                    # right before the divide; a zero-check guard often tests a
                    # *different* register loaded from that same slot. Resolve the
                    # divisor's source slot so a guard on any reg aliasing it
                    # counts (preserving the zero-false-positive posture).
                    slot = self._aarch64_divisor_slot(insns, idx, aliases)
                    if self._aarch64_divisor_is_guarded(
                        insns, idx, aliases, aarch64_cond_branches, slot
                    ):
                        continue
                else:
                    divisor = insn.op_str.strip()
                    if not divisor:
                        continue
                    # Divisor register aliases we look for in a preceding guard.
                    # For a memory divisor we match the whole operand string.
                    if reg_operand.match(divisor) and "[" not in divisor:
                        aliases = {divisor, self._widen(divisor)}
                    else:
                        aliases = {divisor}
                    if self._divisor_is_guarded(insns, idx, aliases, cond_jumps):
                        continue

                results.append(
                    {
                        "address": insn.address,
                        "function": func.name,
                        "divisor": divisor,
                    }
                )
        return results

    @staticmethod
    def _divisor_is_guarded(insns, div_idx, aliases, cond_jumps) -> bool:
        """True if a cmp/test on the divisor precedes the division with a branch.

        Scans the instructions before ``insns[div_idx]`` (bounded window) for a
        ``cmp``/``test`` that mentions a divisor alias and is followed — anywhere
        before the division — by a conditional jump. That compare-and-branch is
        the program's zero-check; its presence means the divisor is guarded.
        """
        window = insns[max(0, div_idx - 24): div_idx]
        saw_compare_on_divisor = False
        for ins in window:
            if ins.mnemonic in ("cmp", "test") and any(
                a in ins.op_str for a in aliases
            ):
                saw_compare_on_divisor = True
            elif saw_compare_on_divisor and ins.mnemonic in cond_jumps:
                return True
        return False

    # An AArch64 stack-slot memory operand, e.g. ``[sp, #0x4]`` / ``[x29, #-8]``.
    _AARCH64_SLOT_RE = re.compile(r"\[(sp|x29)\s*(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\]")
    # ``ldr <wreg/xreg>, [slot]`` — a reload of a stack slot into a register.
    _AARCH64_LDR_RE = re.compile(
        r"^\s*([wx](?:[12]?[0-9]|3[01]))\s*,\s*(\[(?:sp|x29)[^\]]*\])"
    )

    @classmethod
    def _aarch64_divisor_slot(cls, insns, div_idx, aliases) -> str | None:
        """The stack slot the divisor register was last loaded from before the
        division, or ``None`` if it was not a slot reload.

        At -O0 the divisor arrives as ``ldr w9, [sp, #N]`` shortly before the
        ``sdiv``. Returns the normalized slot operand string (``[sp, #0x4]``) so
        a zero-check on any other register loaded from that same slot can be
        recognized as the divisor's guard.
        """
        window = insns[max(0, div_idx - 24): div_idx]
        slot: str | None = None
        for ins in window:
            if ins.mnemonic != "ldr":
                continue
            m = cls._AARCH64_LDR_RE.match(ins.op_str)
            if not m:
                continue
            dest = m.group(1)
            num = dest[1:]
            if f"w{num}" in aliases or f"x{num}" in aliases:
                slot = cls._normalize_slot(m.group(2))
        return slot

    @classmethod
    def _normalize_slot(cls, operand: str) -> str | None:
        """Canonicalize a stack-slot operand to ``base#offset`` for comparison."""
        m = cls._AARCH64_SLOT_RE.search(operand)
        if not m:
            return None
        base = m.group(1)
        off = m.group(2) or "0"
        return f"{base}#{int(off, 0)}"

    @classmethod
    def _aarch64_divisor_is_guarded(
        cls, insns, div_idx, aliases, cond_branches, slot=None
    ) -> bool:
        """True if an AArch64 zero-check on the divisor precedes the division.

        Guard idioms, all bounded to the instructions before the division:

        * ``cbz``/``cbnz`` whose register operand is the divisor (a direct
          compare-and-branch on zero), or
        * ``cmp``/``tst`` that mentions the divisor, followed — anywhere before
          the divide — by a conditional branch (``b.eq``/``b.ne``/...).

        The divisor's w/x views are treated as the same logical register
        (``cbz x9`` guards an ``sdiv ..., w9``). When the divisor was reloaded
        from a stack slot (``slot``), any register loaded from that *same* slot
        is also treated as the divisor — at -O0 the zero-check commonly tests a
        sibling register reloaded from the slot (``cbnz w8`` guarding an
        ``sdiv ..., w9`` where both came from ``[sp, #N]``).
        """
        first_operand = re.compile(r"^\s*([wx](?:[12]?[0-9]|3[01]|zr))\b")

        # Build the live set of registers that alias the divisor (directly or
        # via the shared source slot), scanning forward through the window so a
        # reload's destination becomes a divisor alias from that point on.
        window_start = max(0, div_idx - 24)
        window = insns[window_start: div_idx]

        def slot_alias_regs() -> set[str]:
            regs: set[str] = set()
            if slot is None:
                return regs
            for ins in window:
                if ins.mnemonic != "ldr":
                    continue
                m = cls._AARCH64_LDR_RE.match(ins.op_str)
                if m and cls._normalize_slot(m.group(2)) == slot:
                    dest = m.group(1)
                    num = dest[1:]
                    regs.add(f"w{num}")
                    regs.add(f"x{num}")
            return regs

        all_aliases = set(aliases) | slot_alias_regs()

        saw_compare_on_divisor = False
        for ins in window:
            if ins.mnemonic in ("cbz", "cbnz"):
                m = first_operand.match(ins.op_str)
                if m and m.group(1) in all_aliases:
                    return True
            elif ins.mnemonic in ("cmp", "tst") and any(
                a in ins.op_str.split(",")[0] for a in all_aliases
            ):
                saw_compare_on_divisor = True
            elif saw_compare_on_divisor and ins.mnemonic in cond_branches:
                return True
        return False

    # -- CWE-119 indexed-access discovery (arch-aware) --------------------

    def indexed_memory_access_without_bounds_check(
        self, func: Any
    ) -> tuple[int, str, bool] | None:
        """Find an unguarded scaled-index memory access in ``func``.

        This is the engine half of the CWE-119 (buffer over-read/write via an
        attacker-controlled index) heuristic. It looks for a store or load whose
        *index* is a register-held value derived from a sign/zero-extended int
        (the index-promotion idiom that signals ``arr[i]`` addressing), and which
        is **not** preceded in the same function by a bounds-check compare/branch
        (the clean ``if (i < 0 || i >= N) return;`` guard). Guarded accesses are
        the clean-baseline pattern and are skipped to preserve the
        zero-false-positive posture.

        Returns ``(address, "write"|"read", symbolic_index)`` for the first such
        access, or ``None``. ``symbolic_index`` is True when the offending access
        uses a genuinely data-dependent *register* index (``[rax+rdx]`` on
        x86_64, or an ``add xD, xBase, xIdx`` base+index computation on AArch64)
        rather than resting only on the static index-extension heuristic; the
        check maps that to "high" vs "medium" confidence.

        Architecture-aware. On x86_64 the access is a ``mov``/``movzx``/``movsx``
        with a scaled-index memory operand (``[base+index]``) preceded by a
        ``movsxd``/``cdqe``/``movsx``/``movzx`` index extension, with a ``cmp``
        as the bounds-check signal. On AArch64 the index is sign-extended with
        ``ldrsw xN, [slot]`` (the int index reload) or ``sxtw xN, wM``, the
        address is computed with ``add xD, xBase, xIdx`` (two registers), and the
        dereference is ``str``/``ldr``/``strb``/``ldrb`` through ``[xD]``; the
        bounds-check signal is ``cmp``/``subs``/``tst``/``tbz``/``tbnz``/``cbz``/
        ``cbnz`` followed by a conditional branch. Returns ``None`` on any other
        architecture, so the CWE-119 check is silent there.
        """
        arch = self.project.arch.name
        if arch == "AMD64":
            return self._indexed_access_amd64(func)
        if arch == "AARCH64":
            return self._indexed_access_aarch64(func)
        return None

    @staticmethod
    def _func_insns_sorted(func: Any) -> list[Any]:
        insns: list[Any] = []
        for block in func.blocks:
            try:
                insns.extend(block.capstone.insns)
            except Exception:  # pragma: no cover - defensive
                continue
        insns.sort(key=lambda i: i.address)
        return insns

    # x86_64 index-register conversions that signal "this value is used as an
    # index" (an int promoted to 64-bit for addressing).
    _INDEX_EXT_AMD64: frozenset[str] = frozenset({"movsxd", "cdqe", "movsx", "movzx"})
    # A store/load opcode family we care about on x86_64.
    _MEM_OPS_AMD64: frozenset[str] = frozenset({"mov", "movzx", "movsx"})

    def _indexed_access_amd64(self, func: Any) -> tuple[int, str, bool] | None:
        import re

        # A scaled-index memory operand like [reg+reg], [reg+reg*N], [base+reg].
        scaled_index = re.compile(r"\[[a-z0-9]+\s*\+\s*[a-z0-9]+(?:\s*\*\s*[0-9]+)?\]")
        # A *symbolic* scaled index where the index component is itself a
        # register (register base + register index): [rax+rdx], [rax+rdx*4]. This
        # is distinct from a static [reg+imm] form.
        symbolic_index_re = re.compile(
            r"\[[a-z][a-z0-9]*\s*\+\s*[a-z][a-z0-9]*(?:\s*\*\s*[0-9]+)?\]"
        )

        insns = self._func_insns_sorted(func)
        saw_index_ext = False
        saw_bounds_check = False
        for insn in insns:
            mn, ops = insn.mnemonic, insn.op_str
            if mn in self._INDEX_EXT_AMD64:
                saw_index_ext = True
            # A cmp (followed by a conditional jump) is a (heuristic) bounds check.
            if mn == "cmp":
                saw_bounds_check = True
            if mn not in self._MEM_OPS_AMD64:
                continue
            if not scaled_index.search(ops):
                continue
            if not saw_index_ext:
                # Require evidence the index came from a sign/zero-extended value
                # (the signature of an int index promoted to 64-bit addressing).
                continue
            if saw_bounds_check:
                # A guarded access is the clean-baseline pattern; skip it.
                return None
            # write if the memory operand is the dest.
            kind = "write" if ops.strip().startswith("[") or self._amd64_dest_is_mem(ops) else "read"
            symbolic_index = bool(symbolic_index_re.search(ops))
            return (insn.address, kind, symbolic_index)
        return None

    @staticmethod
    def _amd64_dest_is_mem(ops: str) -> bool:
        # `mov [mem], reg` => first operand (dest) is memory.
        first = ops.split(",", 1)[0].strip()
        return first.startswith("[") or "ptr [" in first

    # AArch64 sign/zero-extension forms that promote a 32-bit int index to a
    # 64-bit address offset — the analogue of x86_64 ``movsxd``/``cdqe``. ``ldrsw``
    # loads and sign-extends a 32-bit slot (the int-index reload at -O0); ``sxtw``
    # sign-extends a w-register already in hand.
    _INDEX_EXT_AARCH64: frozenset[str] = frozenset({"ldrsw", "sxtw"})
    # AArch64 load/store mnemonics for a byte/half/word/dword access.
    _MEM_OPS_AARCH64: frozenset[str] = frozenset({
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldur", "ldurb",
        "str", "strb", "strh", "stur", "sturb",
    })
    # Bounds-check signal mnemonics on AArch64. A compare/test (cmp/subs/tst) is
    # paired with a conditional branch; tbz/tbnz/cbz/cbnz are self-contained
    # test-and-branch guards. Any of these before the access means it is guarded.
    _BOUNDS_CHECK_AARCH64: frozenset[str] = frozenset({
        "cmp", "subs", "tst", "tbz", "tbnz", "cbz", "cbnz",
    })

    def _indexed_access_aarch64(self, func: Any) -> tuple[int, str, bool] | None:
        import re

        # add xD, xBase, xIdx — a base+index address computation combining two
        # distinct registers (the AArch64 way of forming arr+i at -O0). The
        # x29/sp/wzr/xzr registers are stack/zero and not data-dependent indices.
        add_reg_re = re.compile(r"^(x[0-9]+|w[0-9]+),\s*(x[0-9]+|w[0-9]+),\s*(x[0-9]+|w[0-9]+)\s*$")
        # A dereference through a base register: `[xN]` / `[xN, #imm]`.
        deref_base_re = re.compile(r"\[(x[0-9]+|sp|x29)")

        insns = self._func_insns_sorted(func)

        saw_index_ext = False
        saw_bounds_check = False
        # Registers currently holding a computed base+index address (symbolic).
        index_addr_regs: set[str] = set()

        for insn in insns:
            mn, ops = insn.mnemonic, insn.op_str

            if mn in self._INDEX_EXT_AARCH64:
                saw_index_ext = True

            if mn in self._BOUNDS_CHECK_AARCH64:
                saw_bounds_check = True

            # Track a base+index address computation into a destination register.
            if mn == "add":
                m = add_reg_re.match(ops)
                if m:
                    dst, src1, src2 = m.group(1), m.group(2), m.group(3)
                    if src2 not in ("xzr", "wzr") and src1 not in ("xzr", "wzr"):
                        index_addr_regs.add(dst)
                        continue
                # An add that redefines a tracked base reg with a non-index form
                # invalidates it.
                first = ops.split(",", 1)[0].strip()
                index_addr_regs.discard(first)
                continue

            if mn not in self._MEM_OPS_AARCH64:
                continue

            # Determine the memory operand (the bracketed term) and its base.
            base_m = deref_base_re.search(ops)
            if not base_m:
                continue
            base_reg = base_m.group(1)

            # The access is a candidate only if its base register was computed as
            # a base+index sum (symbolic) OR we at least saw an index extension
            # (the static heuristic) and the access reads/writes a buffer through
            # a non-stack base register.
            symbolic_index = base_reg in index_addr_regs
            if not symbolic_index and not saw_index_ext:
                continue
            if not symbolic_index and base_reg in ("sp", "x29"):
                # A plain stack-slot spill/reload with no index sum is not an
                # indexed buffer access — skip to avoid false positives.
                continue
            if saw_bounds_check:
                # A guarded access is the clean-baseline pattern; skip it.
                return None

            kind = "write" if mn.startswith("st") else "read"
            return (insn.address, kind, symbolic_index)
        return None

    # Allocators whose return value is NULL on failure and must be NULL-checked
    # before the returned pointer is dereferenced. ``malloc``/``calloc``/
    # ``realloc`` return NULL when the allocation fails; ``strdup``/``strndup``
    # and ``getenv`` likewise return NULL (no such variable / OOM). The result
    # pointer is returned in the architecture's first return register — ``rax``
    # on SysV x86_64, ``x0`` on AAPCS64 AArch64.
    _NULLABLE_ALLOCATORS: frozenset[str] = frozenset({
        "malloc", "calloc", "realloc", "reallocarray",
        "strdup", "strndup",
        "getenv", "secure_getenv",
    })

    def unchecked_alloc_dereferences(self) -> list[dict[str, Any]]:
        """Find allocator results dereferenced without an intervening NULL-check.

        Detects the CWE-476 (NULL Pointer Dereference) pattern that dominates
        real-world C code: a call to a NULL-returning allocator
        (``malloc``/``calloc``/``realloc``/``strdup``/``getenv`` …) whose result
        pointer is dereferenced — read or written through — *before* the program
        tests it against NULL. ``p = malloc(n); p[0] = ...;`` with no
        ``if (p == NULL)`` is the textbook case: when the allocation fails the
        store faults on the NULL page (SIGSEGV), and on some targets an attacker
        who can force the failure turns the crash into a controlled write.

        x86_64 SysV returns the pointer in ``rax``. -O0 codegen spills ``rax`` to
        a stack slot immediately after the call; a later use reloads the slot
        into a register and dereferences it (``mov rax,[rbp-N]; mov [rax],...``
        or ``... [rax]``). This walks each function in address order and, for
        every allocator call, locates the stack slot the result was stored into,
        then scans forward for the first dereference through a register that
        aliases that slot. A site is reported only if **no NULL-check guard**
        (a ``test``/``cmp`` on the result register or the slot, followed by a
        conditional branch) appears between the call and that dereference.

        Excluding guarded sites is what preserves autopsy's zero-false-positive
        posture: ``p = malloc(n); if (!p) return; p[0] = ...;`` checks before it
        uses and must stay silent. A result that is never spilled to a slot, or
        never dereferenced, or dereferenced only after a guard, is not reported.

        Unlike the taint-flow checks (CWE-78/134), CWE-476 needs no
        attacker-input source: the missing NULL-check is the weakness itself,
        regardless of any input path — which is how MITRE frames it.

        Returns one dict per unchecked dereference:
        ``{"address": int, "function": str, "alloc_name": str,
        "alloc_address": int, "slot": str}`` — ``address`` is the dereference,
        ``alloc_address`` the allocator call.

        Arch-aware (x86_64 + AArch64). The x86_64 (SysV) implementation reads
        the result register ``rax`` and recognizes ``test reg, reg`` / ``cmp
        reg, 0`` + conditional-jump guards. The AArch64 (AAPCS64) path tracks
        the result register ``x0`` spilled into a stack slot via ``str x0,
        [sp,#N]`` / ``[x29,#N]``, follows reloads (``ldr xR, [sp,#N]``) and
        register copies (``mov xA, xB``) to build the alias set, recognizes the
        AArch64 NULL-check guard idioms (``cbz``/``cbnz`` on a slot-aliased
        register; ``cmp xR, #0`` / ``cmp xR, xzr`` / ``tst xR, xR`` followed by
        a ``b.<cond>`` branch), and reports the first dereference through an
        aliasing register where the base is not a frame/stack register
        (``sp``/``x29``/``fp``). On any other architecture this returns an empty
        list.
        """
        arch = self.project.arch.name
        if arch == "AMD64":
            return self._unchecked_alloc_dereferences_amd64()
        if arch == "AARCH64":
            return self._unchecked_alloc_dereferences_aarch64()
        return []

    def _unchecked_alloc_dereferences_amd64(self) -> list[dict[str, Any]]:
        """x86_64 (SysV) implementation of :meth:`unchecked_alloc_dereferences`."""
        import re

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        # rax (or eax) spilled to a stack slot right after the alloc returns.
        store_rax = re.compile(
            r"^(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\],\s*(rax|eax)$"
        )
        # reg <- [slot]: a reload of the result slot into a register.
        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        # reg <- reg: register-copy alias propagation.
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")
        # A dereference: any memory operand whose base register we resolved as an
        # alias of the result pointer, e.g. `[rax]`, `qword ptr [rax + 8]`.
        deref_base = re.compile(r"\[(r[a-z0-9]+)")
        # NULL-check guard idioms on a register: `test rax, rax`, `cmp rax, 0`.
        cond_jumps = {
            "je", "jz", "jne", "jnz", "jbe", "jb", "ja", "jae",
            "jle", "jl", "jg", "jge", "js", "jns",
        }

        results: list[dict[str, Any]] = []
        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in call_mnemonics:
                    continue
                target = self._resolve_call_target(insn, cfg)
                if target not in self._NULLABLE_ALLOCATORS:
                    continue

                # Find the slot the result (rax) is spilled into, in the few
                # instructions immediately after the call. If the result is never
                # spilled we cannot track it conservatively -> skip.
                slot: str | None = None
                spill_idx = idx
                for j in range(idx + 1, min(idx + 5, len(insns))):
                    if insns[j].mnemonic == "mov":
                        ms = store_rax.match(insns[j].op_str)
                        if ms:
                            slot = f"{ms.group(1)}{ms.group(2).replace(' ', '')}"
                            spill_idx = j
                            break
                    # A second call before the spill clobbers rax -> give up.
                    if insns[j].mnemonic in call_mnemonics:
                        break
                if slot is None:
                    continue

                self._record_unchecked_deref(
                    insns, spill_idx, slot, func.name, target, insn.address,
                    load_slot, reg_copy, deref_base, cond_jumps, results,
                )

        return results

    @staticmethod
    def _record_unchecked_deref(
        insns, spill_idx, slot, func_name, alloc_name, alloc_address,
        load_slot, reg_copy, deref_base, cond_jumps, results,
    ) -> None:
        """Scan forward from a result spill for an unguarded dereference.

        Tracks the registers that alias the result ``slot`` and the result
        value itself. If a NULL-check guard (``test``/``cmp`` on the slot or an
        aliasing register, followed by a conditional branch) is seen first, the
        site is guarded and nothing is recorded. Otherwise the first
        dereference through an aliasing register is appended to ``results``.
        """
        alias_regs: set[str] = set()
        for insn in insns[spill_idx + 1:]:
            op = insn.op_str

            # A reload of the result slot establishes a fresh alias register.
            ml = load_slot.match(op)
            if insn.mnemonic == "mov" and ml and \
                    f"{ml.group(2)}{ml.group(3).replace(' ', '')}" == slot:
                alias_regs.add(ml.group(1))
                continue

            # Register-copy propagation of an existing alias.
            mc = reg_copy.match(op)
            if insn.mnemonic == "mov" and mc and mc.group(2) in alias_regs:
                alias_regs.add(mc.group(1))
                continue

            # A NULL-check on the slot or an aliasing register, followed (this
            # scan) by a conditional branch, guards the pointer -> not a finding.
            if insn.mnemonic in ("test", "cmp"):
                # Slot strings are stored space-normalized (``rbp-8``) but
                # capstone renders memory operands with spaces (``[rbp - 8]``);
                # compare against the whitespace-stripped op_str.
                op_nospace = op.replace(" ", "")
                touches_slot = slot in op_nospace
                touches_alias = any(a in op for a in alias_regs)
                if touches_slot or touches_alias:
                    # Look ahead for the conditional branch that consumes the
                    # flags this compare set; its presence is the guard.
                    after = insns[insns.index(insn) + 1: insns.index(insn) + 6]
                    if any(nx.mnemonic in cond_jumps for nx in after):
                        return
                continue

            # A dereference through an aliasing register, where the register is
            # the *base* of a memory operand (not merely mentioned). The store
            # form `mov [rax], src` and any read `... [rax+8]` both qualify.
            md = deref_base.search(op)
            if md and md.group(1) in alias_regs:
                results.append(
                    {
                        "address": insn.address,
                        "function": func_name,
                        "alloc_name": alloc_name,
                        "alloc_address": alloc_address,
                        "slot": slot,
                    }
                )
                return

    # ----- AArch64 NULL-deref (CWE-476) ----------------------------------
    #
    # AAPCS64: an allocator returns the pointer in ``x0``. -O0 codegen spills it
    # to a stack slot immediately after the call (``str x0, [sp, #N]`` or
    # ``[x29, #N]``); a later use reloads the slot into a register
    # (``ldr xR, [sp, #N]``) and dereferences it (``str``/``ldr ..., [xR]``).
    # The NULL-check guard idioms are: ``cbz``/``cbnz`` on a slot-aliased
    # register, or ``cmp xR, #0`` / ``cmp xR, xzr`` / ``tst xR, xR`` followed
    # by a ``b.<cond>`` branch.
    _AARCH64_STORE_X0 = re.compile(
        r"^x0,\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
    )
    _AARCH64_LOAD_SLOT = re.compile(
        r"^(x[0-9]+),\s*\[(sp|x29|fp)(?:,\s*(#[+\-]?(?:0x[0-9a-f]+|\d+)))?\]$"
    )
    _AARCH64_REG_COPY = re.compile(r"^(x[0-9]+),\s*(x[0-9]+)$")
    # Match the base register inside a bracketed memory operand; bare ``[xR]``
    # or ``[xR, #N]`` / ``[xR, xI, lsl #N]``. The ``(?!\d)`` keeps ``x1`` from
    # accidentally swallowing the ``1`` of ``x10`` etc. (capstone already
    # renders distinct names so this is belt-and-braces).
    _AARCH64_DEREF_BASE = re.compile(r"\[(x[0-9]+|sp|x29|fp)(?!\d)")
    _AARCH64_FRAME_REGS = frozenset({"sp", "x29", "fp"})
    # AArch64 conditional branches. ``b.<cond>`` is rendered as one mnemonic
    # token by capstone (``b.eq``, ``b.ne``, ``b.lt``, ...). ``cbz``/``cbnz``
    # and ``tbz``/``tbnz`` are register-test branches that act as the guard
    # without a preceding compare.
    _AARCH64_COND_BRANCHES = frozenset({
        "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
        "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.cs", "b.cc",
        "b.hs", "b.lo",
        "cbz", "cbnz", "tbz", "tbnz",
    })

    def _unchecked_alloc_dereferences_aarch64(self) -> list[dict[str, Any]]:
        """AArch64 (AAPCS64) implementation of :meth:`unchecked_alloc_dereferences`.

        Mirrors the x86_64 walker but uses AAPCS64 register conventions and
        AArch64 spill/reload/guard mnemonics. The allocator's return register
        is ``x0``; the spill is ``str x0, [sp, #N]`` / ``[x29, #N]``; a slot
        reload is ``ldr xR, [base, #N]``; a register copy is ``mov xA, xB``;
        and a dereference is any memory operand whose base register is a
        non-frame GPR that aliases the result slot. A NULL-check guard is
        either ``cbz``/``cbnz`` on a slot-aliased register, or a
        ``cmp``/``tst`` on the slot/alias followed by ``b.<cond>``.
        """
        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()
        results: list[dict[str, Any]] = []

        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue
            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            for idx, insn in enumerate(insns):
                if insn.mnemonic not in call_mnemonics:
                    continue
                target = self._resolve_call_target(insn, cfg)
                if target not in self._NULLABLE_ALLOCATORS:
                    continue

                # Find the slot the result (x0) is spilled into in the few
                # instructions immediately after the call.
                slot: str | None = None
                spill_idx = idx
                for j in range(idx + 1, min(idx + 5, len(insns))):
                    nxt = insns[j]
                    if nxt.mnemonic == "str":
                        ms = self._AARCH64_STORE_X0.match(nxt.op_str)
                        if ms:
                            off = ms.group(2) if ms.lastindex and ms.lastindex >= 2 else None
                            if off is None:
                                off = "+0"
                            slot = f"{ms.group(1)}{off.replace(' ', '').lstrip('#')}"
                            spill_idx = j
                            break
                    # A second call before the spill clobbers x0 -> give up.
                    if nxt.mnemonic in call_mnemonics:
                        break
                if slot is None:
                    continue

                self._record_unchecked_deref_aarch64(
                    insns, spill_idx, slot, func.name, target, insn.address, results,
                )

        return results

    @classmethod
    def _record_unchecked_deref_aarch64(
        cls, insns, spill_idx, slot, func_name, alloc_name, alloc_address, results,
    ) -> None:
        """Scan forward from an AArch64 result spill for an unguarded dereference.

        Builds the alias-register set from slot reloads and register-to-register
        copies. A NULL-check guard on the slot or an aliasing register —
        ``cbz``/``cbnz`` directly, or a ``cmp``/``tst`` on the slot/alias
        followed within a small window by a ``b.<cond>`` — terminates the scan
        without recording. Otherwise the first dereference through an aliasing
        register (where the base is not a frame register) is appended.
        """
        alias_regs: set[str] = set()
        scan = insns[spill_idx + 1:]
        for i, insn in enumerate(scan):
            op = insn.op_str

            # A reload of the result slot establishes a fresh alias register.
            if insn.mnemonic == "ldr":
                ml = cls._AARCH64_LOAD_SLOT.match(op)
                if ml:
                    base = ml.group(2)
                    off = ml.group(3) if ml.lastindex and ml.lastindex >= 3 else None
                    if off is None:
                        off = "+0"
                    key = f"{base}{off.replace(' ', '').lstrip('#')}"
                    if key == slot:
                        alias_regs.add(ml.group(1))
                        continue

            # Register-copy propagation of an existing alias.
            if insn.mnemonic == "mov":
                mc = cls._AARCH64_REG_COPY.match(op)
                if mc and mc.group(2) in alias_regs:
                    alias_regs.add(mc.group(1))
                    continue

            # cbz/cbnz on an aliasing register is a direct NULL-check guard.
            if insn.mnemonic in ("cbz", "cbnz"):
                # op_str is ``xR, <label>``; the register is the first token.
                first = op.split(",", 1)[0].strip()
                if first in alias_regs:
                    return
                continue

            # tbz/tbnz: bit-test branch. Only the sign-bit or bit-0 test on an
            # alias would constitute a meaningful guard; conservatively treat
            # any tbz/tbnz on an aliasing register as a guard so the scan stays
            # silent on defensively-written code (false-negative bias preserves
            # the zero-false-positive posture).
            if insn.mnemonic in ("tbz", "tbnz"):
                first = op.split(",", 1)[0].strip()
                if first in alias_regs:
                    return
                continue

            # cmp/tst on the slot or an alias, followed within a small window
            # by a conditional branch, is a NULL-check guard.
            if insn.mnemonic in ("cmp", "tst"):
                touches_alias = any(
                    re.search(rf"\b{re.escape(a)}\b", op) for a in alias_regs
                )
                if touches_alias:
                    after = scan[i + 1: i + 6]
                    if any(nx.mnemonic in cls._AARCH64_COND_BRANCHES for nx in after):
                        return
                continue

            # A dereference through an aliasing register (non-frame base) is the
            # unguarded use. Both stores (``str wzr, [x9]``) and loads (``ldr
            # w0, [x9, #4]``) qualify; we report the first one.
            md = cls._AARCH64_DEREF_BASE.search(op)
            if md:
                base = md.group(1)
                if base not in cls._AARCH64_FRAME_REGS and base in alias_regs:
                    results.append(
                        {
                            "address": insn.address,
                            "function": func_name,
                            "alloc_name": alloc_name,
                            "alloc_address": alloc_address,
                            "slot": slot,
                        }
                    )
                    return

    @staticmethod
    def _widen(reg: str) -> str:
        """Map a 32-bit sub-register name to its 64-bit form (edx -> rdx)."""
        if reg.startswith("e") and len(reg) >= 2:
            return "r" + reg[1:]
        return reg

    @staticmethod
    def _reg_in(reg: str, aliases: set[str]) -> bool:
        """True if ``reg`` (or its 64-bit widening) is in the alias set."""
        return reg in aliases or AngrEngine._widen(reg) in aliases

    # File-system *check* functions that inspect a path by name (CWE-367
    # time-of-check). Each tests a property of a path string but does not open
    # it, so the property it observed can change before the matching use.
    _TOCTOU_CHECK_FNS: frozenset[str] = frozenset({
        "access", "faccessat", "faccessat2",
        "stat", "stat64", "lstat", "lstat64", "fstatat", "fstatat64",
        "__xstat", "__lxstat", "__xstat64", "__lxstat64",
    })

    # File-system *use* functions that act on a path by name (CWE-367
    # time-of-use). Operating by name (rather than on a descriptor) is what
    # makes the use racy: the path may now resolve to a different object than
    # the one the check inspected.
    _TOCTOU_USE_FNS: frozenset[str] = frozenset({
        "open", "open64", "openat", "openat64", "creat", "creat64",
        "fopen", "fopen64", "freopen",
        "unlink", "unlinkat", "remove", "rename", "renameat",
        "chmod", "chown", "lchown", "symlink", "link", "mkdir", "rmdir",
        "truncate",
    })

    def toctou_check_then_use_sequences(self) -> list[dict[str, Any]]:
        """Find time-of-check/time-of-use (CWE-367) check→use sequences.

        Detects the classic TOCTOU race where a program first *checks* a path
        by name (``access``/``stat``/``lstat`` and friends — the time of check)
        and then later, in the same function, *uses* a path by name
        (``open``/``fopen``/``creat``/``unlink`` etc. — the time of use). The
        property the check observed (existence, permission, type) can change in
        the interval, so an attacker who wins the race (commonly by swapping the
        path for a symlink) makes the program operate on a different object than
        the one it vetted — the ``access()``-before-``open()`` privilege bug
        being the textbook case (CWE-367 / CWE-363).

        The detector is purely call-site-driven: it resolves direct calls by
        symbol name and never inspects registers, so it is architecture-agnostic
        (runs identically on x86_64 ``call`` and AArch64 ``bl``). For each
        function it walks the instruction stream in address order; once a check
        call is seen, the *next* by-name use call in the same function is
        reported as the time-of-use that closes the window. Only the first use
        after a check fires (one finding per check), keeping the signal tight.

        Zero-false-positive posture: a function that only checks (no following
        use) or only uses (no preceding check) is silent — the race needs both
        halves co-located. The descriptor-based safe pattern
        (``open`` then ``fstat``/``fchmod`` on the returned ``fd``) does not
        match: ``fstat``/``fchmod`` operate on a descriptor, not a path, so they
        are deliberately absent from both sets and never trigger a finding.

        Each returned dict describes one race:
            {
                "function":      caller function name,
                "check_name":    the time-of-check symbol (e.g. "access"),
                "check_address": address of the check call instruction,
                "use_name":      the time-of-use symbol (e.g. "open"),
                "use_address":   address of the use call instruction,
            }
        """
        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()
        results: list[dict[str, Any]] = []

        for func in cfg.kb.functions.values():
            if getattr(func, "is_plt", False) or getattr(func, "is_simprocedure", False):
                continue

            insns: list[Any] = []
            for block in func.blocks:
                try:
                    insns.extend(block.capstone.insns)
                except Exception:  # pragma: no cover - defensive
                    continue
            insns.sort(key=lambda i: i.address)

            pending_check: tuple[str, int] | None = None
            for insn in insns:
                if insn.mnemonic not in call_mnemonics:
                    continue
                target = self._resolve_call_target(insn, cfg)
                if target is None:
                    continue
                if pending_check is None:
                    if target in self._TOCTOU_CHECK_FNS:
                        pending_check = (target, insn.address)
                    continue
                # We have an open check; the next by-name use closes the window.
                if target in self._TOCTOU_USE_FNS:
                    check_name, check_addr = pending_check
                    results.append(
                        {
                            "function": func.name,
                            "check_name": check_name,
                            "check_address": check_addr,
                            "use_name": target,
                            "use_address": insn.address,
                        }
                    )
                    pending_check = None
                elif target in self._TOCTOU_CHECK_FNS:
                    # A second check before any use: re-anchor on the latest one
                    # (its window is the one closest to the eventual use).
                    pending_check = (target, insn.address)

        return results

    def _resolve_call_target(self, insn: Any, cfg: Any) -> str | None:
        """Resolve a call instruction's target to a symbol name if possible.

        Handles both the x86_64 ``call`` operand form (``0x401199``) and the
        AArch64 ``bl`` operand form, which capstone renders with a leading
        immediate marker (``#0x210218``).
        """
        op = insn.op_str.strip()
        # AArch64 immediates carry a leading '#'; strip it so the hex target
        # parses the same as the x86_64 form.
        if op.startswith("#"):
            op = op[1:]
        try:
            target_addr = int(op, 16) if op.startswith("0x") else None
        except ValueError:
            target_addr = None
        if target_addr is None:
            return None
        # Direct call into a known function (often a PLT stub).
        func = cfg.kb.functions.get(target_addr)
        if func is not None and func.name:
            name = func.name
            # Strip common PLT decorations.
            return name.split("@")[0]
        # Fall back to the loader's symbol table.
        sym = self.project.loader.find_symbol(target_addr)
        if sym is not None and sym.name:
            return sym.name.split("@")[0]
        return None

    # -- Symbolic, state-capped reachability -----------------------------

    def reachability_pass(self, max_steps: int = 200) -> int:
        """Run a bounded symbolic reachability pass from the entry point.

        This drives angr's symbolic executor over the program with stdin
        modeled as a symbolic file. It enforces ``self.max_states`` as a cap on
        the *cumulative number of symbolic states processed*: each exploration
        step contributes the count of its active states, and once the running
        total exceeds the cap a :class:`StateLimitExceeded` is raised.

        This is the resource governor required by the ``--max-states`` flag: a
        small cap (e.g. 10) trips on any non-trivial program, while the default
        (1000) comfortably completes the small v0.1 fixtures.

        Returns:
            The cumulative number of symbolic states processed.
        """
        angr = self._angr
        state = self.project.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", has_end=True)
        )
        simgr = self.project.factory.simulation_manager(state)

        cumulative = 0

        def _step(sm):
            nonlocal cumulative
            cumulative += len(sm.active)
            if cumulative > self.max_states:
                raise StateLimitExceeded(
                    f"state limit exceeded (>{self.max_states} states)"
                )
            return sm

        try:
            simgr.run(step_func=_step, n=max_steps)
        except StateLimitExceeded:
            raise
        except Exception as exc:  # pragma: no cover - slow path
            raise EngineError(f"symbolic reachability pass failed: {exc}") from exc
        return cumulative
