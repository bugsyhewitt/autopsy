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

    def assert_supported(self) -> None:
        """Reject non-ELF / non-x86_64 targets (v0.1 scope guard)."""
        arch_name = self.project.arch.name
        if arch_name != "AMD64":
            raise EngineError(
                f"unsupported architecture {arch_name!r}; v0.1 supports x86_64 (AMD64) only"
            )

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

    def call_sites_to(self, names: set[str]) -> list[CallSite]:
        """Find every call to an imported function whose name is in ``names``.

        Walks the CFG call graph and resolves PLT/extern targets back to their
        symbol names. Used by the CWE-190 (malloc), CWE-78 (system/execve), and
        CWE-416 (malloc/free) checks.
        """
        cfg = self.cfg()
        results: list[CallSite] = []
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                try:
                    insns = block.capstone.insns
                except Exception:  # pragma: no cover - defensive
                    continue
                for insn in insns:
                    if insn.mnemonic != "call":
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
        """Resolve a call instruction's target to a symbol name if possible."""
        op = insn.op_str.strip()
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
