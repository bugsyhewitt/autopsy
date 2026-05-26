"""Finding data structures and JSON report serialization.

This module is intentionally angr-free: it only describes the shape of a
finding and how a collection of findings is serialized. The fast unit-test
layer exercises this module directly without touching angr.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class TaintPoint:
    """A single program point along a taint trace.

    Attributes:
        address: Instruction address (int) for the program point.
        description: Human-readable note about what happens here (e.g.
            "tainted input read from stdin", "value reaches malloc size arg").
    """

    address: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"address": hex(self.address), "description": self.description}


@dataclass(frozen=True)
class Finding:
    """A single vulnerability finding emitted by a check.

    The serialized form is the public contract verified by the v0.1 criteria:
    every finding must carry ``cwe``, ``function``, ``address``, ``taint_trace``
    (array of program points), and ``evidence``.
    """

    cwe: int
    function: str
    address: int
    evidence: str
    taint_trace: list[TaintPoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "function": self.function,
            "address": hex(self.address),
            "taint_trace": [p.to_dict() for p in self.taint_trace],
            "evidence": self.evidence,
        }


@dataclass
class Report:
    """The full analysis result for one binary."""

    binary: str
    checks: list[int]
    findings: list[Finding] = field(default_factory=list)
    state_limit_exceeded: bool = False
    max_states: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "checks": self.checks,
            "max_states": self.max_states,
            "state_limit_exceeded": self.state_limit_exceeded,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
