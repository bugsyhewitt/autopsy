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

    # CWE checks whose detection is purely call-site-driven (call-graph + import
    # symbol resolution) and therefore architecture-agnostic. These run on any
    # architecture in ``SUPPORTED_ARCHS``. CWE-676 (dangerous-function use) and
    # CWE-377 (insecure temporary file) are call-site-driven like CWE-78/190 —
    # they resolve direct calls by symbol name and never inspect registers, so
    # they are sound on AArch64 too. CWE-338 (weak-PRNG use) is the same shape —
    # it resolves direct calls by symbol name and never inspects registers.
    # CWE-367 (TOCTOU check->use) is likewise call-site-driven (it pairs a
    # by-name check call with a following by-name use call) and never inspects
    # registers, so it runs on AArch64 too.
    _ARCH_AGNOSTIC_CHECKS: tuple[int, ...] = (78, 190, 338, 367, 377, 676)

    def assert_supported(self) -> None:
        """Reject targets on architectures autopsy cannot analyze.

        x86_64 (AMD64) is fully supported. AArch64 (ARM64) is supported for the
        call-site-driven checks (CWE-78, CWE-190); the register-level checks
        (CWE-119/415/416/732/787) use x86_64 register conventions and report no
        findings on AArch64 — see :meth:`checks_supported_on_arch`.
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

        On x86_64 every check runs. On AArch64 only the architecture-agnostic,
        call-site-driven checks (CWE-78, CWE-190) run; the register-level checks
        rely on x86_64 register-name literals and would silently mis-analyze
        AArch64, so they are skipped rather than producing unsound results.

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
                "fmt_reg":     the format-argument register (e.g. "rdi"),
                "fmt_slot":    the stack slot the format pointer was loaded from,
            }

        x86_64 only: the format-argument register mapping uses the SysV calling
        convention and the slot/aliasing tracking assumes -O0 stack-slot spill
        conventions. AArch64 register conventions differ, so this returns no
        sinks on non-AMD64 targets (the caller check is arch-gated upstream).
        """
        import re

        if self.project.arch.name != "AMD64":
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        # reg <- [rbp/rsp +/- N]: a stack-slot reload (non-literal format).
        load_slot = re.compile(
            r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[(rbp|rsp)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))\]$"
        )
        # reg <- reg: a register copy (alias propagation).
        reg_copy = re.compile(r"^(r[a-z0-9]+),\s*(r[a-z0-9]+)$")
        # reg <- [rip + disp] (lea) or an immediate: a constant rodata pointer.
        lea_rip = re.compile(r"^(r[a-z0-9]+),\s*(?:qword ptr )?\[rip\s*[+\-]")
        mov_imm = re.compile(r"^(r[a-z0-9]+),\s*(?:0x[0-9a-f]+|\d+)$")

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
                fmt_reg = self._FORMAT_SINK_FMT_REG.get(target)
                if fmt_reg is None:
                    continue

                # Walk back from the call resolving how the format register was
                # last set. Track the set of registers currently aliasing the
                # format register so a `mov fmt_reg, rax; mov rax, [slot]`
                # sequence is followed correctly.
                fmt_aliases: set[str] = {fmt_reg}
                fmt_slot: str | None = None
                literal = False
                for prev in reversed(insns[max(0, idx - 12): idx]):
                    if prev.mnemonic == "lea":
                        ml = lea_rip.match(prev.op_str)
                        if ml and ml.group(1) in fmt_aliases:
                            literal = True
                            break
                    if prev.mnemonic == "mov":
                        # lea-style not used, but a direct immediate address.
                        mi = mov_imm.match(prev.op_str)
                        if mi and mi.group(1) in fmt_aliases:
                            literal = True
                            break
                        ms = load_slot.match(prev.op_str)
                        if ms and ms.group(1) in fmt_aliases:
                            fmt_slot = f"{ms.group(2)}{ms.group(3).replace(' ', '')}"
                            break
                        mc = reg_copy.match(prev.op_str)
                        if mc and mc.group(1) in fmt_aliases:
                            # dest aliases the format reg; its source now does too.
                            fmt_aliases.add(mc.group(2))
                            continue

                if literal or fmt_slot is None:
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

        x86_64 only: the length-argument register mapping uses the SysV calling
        convention. On non-AMD64 targets this returns ``False`` (the register
        checks are arch-gated upstream and the heuristic stays conservative).
        """
        import re

        if self.project.arch.name != "AMD64":
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

        x86_64 only: the mode-argument register mapping uses the SysV calling
        convention and the immediate/aliasing tracking assumes -O0 codegen.
        Returns an empty list on non-AMD64 targets.
        """
        import re

        if self.project.arch.name != "AMD64":
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        # reg <- immediate: a compile-time constant mode. -O0 materializes a
        # small octal literal with a 32-bit move (`mov esi, 0x1ff` for 0o777).
        mov_imm = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*((?:0x[0-9a-f]+)|\d+)$")
        # reg <- reg: a register copy (alias propagation).
        reg_copy = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(r[a-z0-9]+|e[a-z0-9]+)$")
        # reg <- [rbp/rsp +/- N]: a stack-slot reload (runtime-computed mode).
        load_slot = re.compile(
            r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(?:[a-z]+ ptr )?\[(rbp|rsp)\s*[+\-]"
        )

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
                mode_reg = self._CHMOD_SINK_MODE_REG.get(target)
                if mode_reg is None:
                    continue

                # The 32-bit sub-register (esi/edx) zero-extends into the 64-bit
                # mode register; -O0 sets a small octal literal via that form.
                mode_aliases = {mode_reg, "e" + mode_reg[1:]}
                mode_val: int | None = None
                for prev in reversed(insns[max(0, idx - 12): idx]):
                    if prev.mnemonic != "mov":
                        # Non-mov touching the mode reg would mean a computed
                        # value we can't resolve; stay conservative and stop.
                        continue
                    mi = mov_imm.match(prev.op_str)
                    if mi and self._reg_in(mi.group(1), mode_aliases):
                        mode_val = int(mi.group(2), 0)
                        break
                    ms = load_slot.match(prev.op_str)
                    if ms and self._reg_in(ms.group(1), mode_aliases):
                        # mode reloaded from a stack slot -> runtime value, unknown.
                        break
                    mc = reg_copy.match(prev.op_str)
                    if mc and self._reg_in(mc.group(1), mode_aliases):
                        mode_aliases = mode_aliases | {mc.group(2), self._widen(mc.group(2))}
                        continue

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

        x86_64 only.
        """
        import re

        if self.project.arch.name != "AMD64":
            return []

        cfg = self.cfg()
        call_mnemonics = self._call_mnemonics()

        mov_imm = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*((?:0x[0-9a-f]+)|\d+)$")
        reg_copy = re.compile(r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(r[a-z0-9]+|e[a-z0-9]+)$")
        load_slot = re.compile(
            r"^(r[a-z0-9]+|e[a-z0-9]+),\s*(?:[a-z]+ ptr )?\[(rbp|rsp)\s*[+\-]"
        )

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
                mask_aliases = {"rdi", "edi"}
                mask_val: int | None = None
                for prev in reversed(insns[max(0, idx - 12): idx]):
                    if prev.mnemonic != "mov":
                        continue
                    mi = mov_imm.match(prev.op_str)
                    if mi and self._reg_in(mi.group(1), mask_aliases):
                        mask_val = int(mi.group(2), 0)
                        break
                    ms = load_slot.match(prev.op_str)
                    if ms and self._reg_in(ms.group(1), mask_aliases):
                        break
                    mc = reg_copy.match(prev.op_str)
                    if mc and self._reg_in(mc.group(1), mask_aliases):
                        mask_aliases = mask_aliases | {mc.group(2), self._widen(mc.group(2))}
                        continue

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

    # Division mnemonics whose divisor (the single explicit operand) can be zero
    # at runtime. ``div``/``idiv`` raise #DE (SIGFPE) when the divisor is 0.
    _DIV_MNEMONICS: frozenset[str] = frozenset({"div", "idiv"})

    def divisions_with_unguarded_divisor(self) -> list[dict[str, Any]]:
        """Find ``div``/``idiv`` sites whose divisor is a non-immediate, unguarded value.

        x86_64 ``div``/``idiv`` take a single explicit operand — the divisor —
        which is always a register or memory location (the instruction has no
        immediate form). The CPU raises a divide-error (#DE → SIGFPE) when that
        divisor is zero. A division is therefore a candidate CWE-369 site unless
        the program *guards* the divisor with a zero-check before the divide.

        For each division this method walks back through the instructions that
        precede it in the same function and looks for a guard: a ``test`` or
        ``cmp`` whose operand mentions the divisor register (or its widening),
        followed by a conditional branch (``je``/``jz``/``jne``/``jnz``/``jbe``/
        ``jb``/etc.). The presence of such a compare-and-branch on the divisor is
        the classic ``if (d == 0) return;`` guard, so guarded sites are excluded
        to preserve the zero-false-positive guarantee on well-written code.

        Returns one dict per *unguarded* division:
        ``{"address": int, "function": str, "divisor": str}``. The list is empty
        on non-AMD64 targets — the divisor-register / guard reasoning relies on
        x86_64 disassembly, so the check is x86_64 only (it is excluded from the
        architecture-agnostic set and skipped on AArch64 upstream).
        """
        import re

        if self.project.arch.name != "AMD64":
            return []

        # The divisor operand of div/idiv: a bare register (``rcx``/``ecx``) or a
        # memory reference (``dword ptr [rbp-4]``). We extract the leading token
        # for register operands; memory operands are reported verbatim.
        reg_operand = re.compile(r"^(?:[a-z]+ ptr )?(?:[er][a-z0-9]+|[a-z]+l|[a-z]+x)$")
        # A zero-check guard: cmp/test naming the divisor, then a conditional jump.
        cond_jumps = {
            "je", "jz", "jne", "jnz", "jbe", "jb", "ja", "jae",
            "jle", "jl", "jg", "jge", "js", "jns",
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
                if insn.mnemonic not in self._DIV_MNEMONICS:
                    continue
                divisor = insn.op_str.strip()
                if not divisor:
                    continue
                # Divisor register aliases we look for in a preceding guard. For a
                # memory divisor we match the whole operand string.
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
