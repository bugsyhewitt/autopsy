"""CWE check registry.

Each check is a callable ``run(engine) -> list[Finding]``. Checks are keyed by
their CWE id so the scope layer can select them. This package is angr-free at
import time; checks only touch angr through the :class:`autopsy.engine.AngrEngine`
object they are handed at call time.
"""

from __future__ import annotations

from typing import Callable

from autopsy.report import Finding

from autopsy.checks import cwe119, cwe125, cwe134, cwe190, cwe338, cwe367, cwe369, cwe377, cwe415, cwe416, cwe476, cwe676, cwe732, cwe78, cwe787

# CWE id -> check callable.
CHECKS: dict[int, Callable[[object], list[Finding]]] = {
    119: cwe119.run,
    125: cwe125.run,
    190: cwe190.run,
    338: cwe338.run,
    367: cwe367.run,
    369: cwe369.run,
    377: cwe377.run,
    415: cwe415.run,
    416: cwe416.run,
    476: cwe476.run,
    78: cwe78.run,
    134: cwe134.run,
    676: cwe676.run,
    732: cwe732.run,
    787: cwe787.run,
}

__all__ = ["CHECKS"]
