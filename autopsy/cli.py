"""Command-line interface for autopsy.

angr-free at import time: the heavy engine is only constructed when a real
analysis runs (inside :func:`autopsy.analyzer.analyze`). Parsing ``--help`` and
arguments never touches angr.
"""

from __future__ import annotations

import argparse
import sys

from autopsy import __version__
from autopsy.scope import VALID_TOKENS

# Exit code returned when --fail-on is satisfied by the findings. Chosen to not
# collide with the existing contract: 0 = clean, 1 = engine error, 2 = state
# limit exceeded. 3 = the findings gate tripped (CI/CD build-break signal).
FAIL_ON_EXIT_CODE = 3

# Confidence levels ordered from least to most specific. A --fail-on threshold
# trips on any finding whose confidence is at or above the chosen level.
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# --fail-on choices. "never" preserves the v0.1 exit-code contract (findings do
# not change the exit code). "any" is an alias for "low" (trip on any finding).
FAIL_ON_CHOICES = ["never", "any", "low", "medium", "high"]


def _gate_tripped(findings, fail_on: str) -> bool:
    """Return True if ``fail_on`` should break the build given ``findings``.

    ``never`` never trips. ``any`` and ``low`` trip on any finding. ``medium``
    and ``high`` trip only when at least one finding meets that confidence
    threshold (findings default to ``"medium"``).
    """
    if fail_on == "never":
        return False
    threshold = _CONFIDENCE_RANK["low" if fail_on == "any" else fail_on]
    for f in findings:
        # Findings whose confidence is unset/unknown are treated as "medium"
        # (the schema default) so the gate never silently ignores them.
        rank = _CONFIDENCE_RANK.get(getattr(f, "confidence", "medium"), 1)
        if rank >= threshold:
            return True
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autopsy",
        description=(
            "angr-backed whole-program binary analysis with CWE-aligned "
            "vulnerability detection (ELF / x86_64)."
        ),
        epilog="Ethical use only: analyze binaries you own or are authorized to assess.",
    )
    parser.add_argument(
        "--binary",
        required=True,
        metavar="PATH",
        help="path to the target ELF binary to analyze",
    )
    parser.add_argument(
        "--checks",
        default="all",
        choices=list(VALID_TOKENS),
        help="which CWE check(s) to run (default: all)",
    )
    parser.add_argument(
        "--max-states",
        type=int,
        default=1000,
        metavar="N",
        help="angr resource cap: max live symbolic states before aborting (default: 1000)",
    )
    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "sarif"],
        help="output format (default: json)",
    )
    parser.add_argument(
        "--fail-on",
        default="never",
        choices=FAIL_ON_CHOICES,
        metavar="LEVEL",
        help=(
            "exit non-zero (code 3) when findings at or above this confidence "
            "are present, for CI/CD build gating: never (default, findings do "
            "not affect exit code), any/low (any finding), medium, high "
            f"(choices: {', '.join(FAIL_ON_CHOICES)})"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"autopsy {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Import the driver lazily so --help stays angr-free and instant.
    from autopsy.analyzer import analyze

    report = analyze(
        binary=args.binary,
        checks_token=args.checks,
        max_states=args.max_states,
    )

    if args.format == "json":
        print(report.to_json())
    elif args.format == "sarif":
        from autopsy.sarif import to_sarif_json
        print(to_sarif_json(report))

    if report.skipped_checks:
        # Some checks were not run on this target's architecture (e.g. the
        # register-level checks on an AArch64 binary). Note it on stderr so the
        # JSON/SARIF on stdout stays machine-clean.
        skipped = ", ".join(f"CWE-{c}" for c in report.skipped_checks)
        print(
            f"note: skipped {skipped} (not supported on this target's architecture)",
            file=sys.stderr,
        )

    if report.state_limit_exceeded:
        # Surface the cap clearly on stderr as well for humans/scripts.
        print(report.error, file=sys.stderr)
        return 2
    if report.error:
        print(report.error, file=sys.stderr)
        return 1

    # CI/CD build gate: if --fail-on is set and matching findings exist, exit
    # non-zero so a pipeline step fails. This runs only after error/state-limit
    # handling so a genuine analysis failure (1/2) is never masked by the gate.
    if _gate_tripped(report.findings, args.fail_on):
        n = len(report.findings)
        print(
            f"fail-on: {n} finding(s) at or above '{args.fail_on}' confidence",
            file=sys.stderr,
        )
        return FAIL_ON_EXIT_CODE
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
