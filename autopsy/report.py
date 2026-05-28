"""Finding data structures and JSON report serialization.

This module is intentionally angr-free: it only describes the shape of a
finding and how a collection of findings is serialized. The fast unit-test
layer exercises this module directly without touching angr.

Internal representation delegates to
:class:`binary_finding_schema.BinaryFinding` and
:class:`binary_finding_schema.TaintTrace` for validation and canonical
serialization. The :class:`Finding` and :class:`TaintPoint` wrappers
preserve the original attribute types and dict shapes that the v0.1 tests
and checks depend on (integer addresses, integer cwe ids).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from binary_finding_schema import BinaryFinding
from binary_finding_schema import TaintTrace as _TaintTrace


class TaintPoint:
    """A single program point along a taint trace.

    Wraps :class:`~binary_finding_schema.TaintTrace` and preserves the
    autopsy-native integer ``address`` attribute.

    Attributes:
        address: Instruction address (int) for the program point.
        description: Human-readable note about what happens here.
    """

    __slots__ = ("_inner", "_address_int")

    def __init__(self, address: int, description: str) -> None:
        self._address_int = address
        self._inner = _TaintTrace(
            address=hex(address),
            description=description,
        )

    @property
    def address(self) -> int:
        return self._address_int

    @property
    def description(self) -> str:
        return self._inner.description

    def to_dict(self) -> dict[str, Any]:
        return {"address": hex(self._address_int), "description": self._inner.description}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintPoint):
            return NotImplemented
        return self._address_int == other._address_int and self.description == other.description

    def __hash__(self) -> int:
        return hash((self._address_int, self.description))

    def __repr__(self) -> str:  # pragma: no cover
        return f"TaintPoint(address={hex(self._address_int)}, description={self.description!r})"


class Finding:
    """A single vulnerability finding emitted by a check.

    Wraps :class:`~binary_finding_schema.BinaryFinding` and preserves the
    autopsy-native attribute types: ``cwe`` and ``address`` are integers,
    matching what checks construct and what unit tests assert.

    The serialized form is the public contract verified by the v0.1 criteria:
    every finding must carry ``cwe``, ``function``, ``address``, ``taint_trace``
    (array of program points), and ``evidence``. A ``confidence`` triage level
    (``"high"``/``"medium"``/``"low"``) is additive — it defaults to
    ``"medium"`` so checks that do not set it remain valid.
    """

    __slots__ = ("_inner", "_cwe_int", "_address_int", "_taint_trace")

    def __init__(
        self,
        cwe: int,
        function: str,
        address: int,
        evidence: str,
        taint_trace: list[TaintPoint] | None = None,
        confidence: str = "medium",
    ) -> None:
        self._cwe_int = cwe
        self._address_int = address
        self._taint_trace: list[TaintPoint] = taint_trace if taint_trace is not None else []
        self._inner = BinaryFinding(
            cwe_id=f"CWE-{cwe}",
            function=function,
            address=hex(address),
            evidence=evidence,
            taint_trace=[
                _TaintTrace(address=hex(tp.address), description=tp.description)
                for tp in self._taint_trace
            ],
            confidence=confidence,
        )

    @property
    def cwe(self) -> int:
        return self._cwe_int

    @property
    def function(self) -> str:
        return self._inner.function

    @property
    def address(self) -> int:
        return self._address_int

    @property
    def evidence(self) -> str:
        return self._inner.evidence

    @property
    def taint_trace(self) -> list[TaintPoint]:
        return list(self._taint_trace)

    @property
    def confidence(self) -> str:
        return self._inner.confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self._cwe_int,
            "function": self._inner.function,
            "address": hex(self._address_int),
            "taint_trace": [p.to_dict() for p in self._taint_trace],
            "evidence": self._inner.evidence,
            "confidence": self._inner.confidence,
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self._cwe_int == other._cwe_int
            and self.function == other.function
            and self._address_int == other._address_int
            and self.evidence == other.evidence
            and self._taint_trace == other._taint_trace
            and self.confidence == other.confidence
        )

    def __hash__(self) -> int:
        return hash((self._cwe_int, self.function, self._address_int, self.evidence))

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"Finding(cwe={self._cwe_int!r}, function={self.function!r}, "
            f"address={hex(self._address_int)}, evidence={self.evidence!r})"
        )


@dataclass
class Report:
    """The full analysis result for one binary."""

    binary: str
    checks: list[int]
    findings: list[Finding] = field(default_factory=list)
    state_limit_exceeded: bool = False
    max_states: int = 0
    error: str | None = None
    # CWE checks that were requested but not run on this target's architecture
    # (e.g. the register-level checks on an AArch64 binary). Additive and
    # default-empty so existing consumers are unaffected.
    skipped_checks: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "checks": self.checks,
            "max_states": self.max_states,
            "state_limit_exceeded": self.state_limit_exceeded,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "skipped_checks": self.skipped_checks,
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
