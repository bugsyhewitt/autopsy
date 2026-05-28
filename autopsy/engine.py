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
