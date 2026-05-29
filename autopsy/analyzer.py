"""Analysis driver: ties the engine and checks together into a Report.

Kept separate from the CLI so it can be unit-tested with a mocked engine.
The angr import only happens when :func:`analyze` constructs a real engine;
callers may inject their own ``engine_factory`` (used by the fast unit tests).
"""

from __future__ import annotations

from typing import Callable

from autopsy.report import Report, Finding
from autopsy.scope import resolve_checks


def _default_engine_factory(binary: str, max_states: int):
    # Imported here so the module top level stays angr-free.
    from autopsy.engine import AngrEngine

    engine = AngrEngine(binary, max_states=max_states)
    engine.assert_supported()
    return engine


def analyze(
    binary: str,
    checks_token: str,
    max_states: int = 1000,
    engine_factory: Callable[[str, int], object] = _default_engine_factory,
) -> Report:
    """Run the selected checks against ``binary`` and return a Report.

    Args:
        binary: Path to the target ELF.
        checks_token: One of "119"/"190"/"416"/"78"/"all".
        max_states: angr resource cap.
        engine_factory: Builds the engine; injectable for tests.
    """
    from autopsy.engine import StateLimitExceeded, EngineError
    from autopsy.checks import CHECKS

    cwes = resolve_checks(checks_token)
    report = Report(binary=binary, checks=cwes, max_states=max_states)

    try:
        engine = engine_factory(binary, max_states)
    except EngineError as exc:
        report.error = str(exc)
        return report

    findings: list[Finding] = []
    try:
        # Resource governor: a bounded symbolic reachability pass that honors
        # --max-states. Trips StateLimitExceeded when the cap is too low.
        # Engines used purely for unit tests (no reachability_pass) skip this.
        pass_fn = getattr(engine, "reachability_pass", None)
        if callable(pass_fn):
            pass_fn()
        # Partition the requested checks by architecture support. On x86_64 all
        # run; on AArch64 the call-site-driven checks plus the arch-aware
        # register-level checks (CWE-732, CWE-190) run and the x86_64-only
        # register-level checks are skipped (recorded, not silently dropped).
        # Unit-test engines without this method run every requested check.
        partition = getattr(engine, "checks_supported_on_arch", None)
        if callable(partition):
            runnable, skipped = partition(cwes)
            report.skipped_checks = skipped
        else:
            runnable = cwes
        for cwe in runnable:
            check = CHECKS[cwe]
            findings.extend(check(engine))
    except StateLimitExceeded as exc:
        report.state_limit_exceeded = True
        report.error = str(exc)
        return report
    except EngineError as exc:
        report.error = str(exc)
        return report

    report.findings = findings
    return report
