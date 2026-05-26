"""CWE check registry.

Each check is a callable ``run(engine) -> list[Finding]``. Checks are keyed by
their CWE id so the scope layer can select them. This package is angr-free at
import time; checks only touch angr through the :class:`autopsy.engine.AngrEngine`
object they are handed at call time.
"""

from __future__ import annotations

from typing import Callable

from autopsy.report import Finding

from autopsy.checks import cwe119, cwe190, cwe415, cwe416, cwe78

# CWE id -> check callable.
CHECKS: dict[int, Callable[[object], list[Finding]]] = {
    119: cwe119.run,
    190: cwe190.run,
    415: cwe415.run,
    416: cwe416.run,
    78: cwe78.run,
}

__all__ = ["CHECKS"]
