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
    # architecture in ``SUPPORTED_ARCHS``.
    _ARCH_AGNOSTIC_CHECKS: tuple[int, ...] = (78, 190)

    def assert_supported(self) -> None:
        """Reject targets on architectures autopsy cannot analyze.

        x86_64 (AMD64) is fully supported. AArch64 (ARM64) is supported for the
        call-site-driven checks (CWE-78, CWE-190); the register-level checks
        (CWE-119/415/416/787) use x86_64 register conventions and report no
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
