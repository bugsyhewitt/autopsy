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
        choices=["json"],
        help="output format (default: json)",
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

    if report.state_limit_exceeded:
        # Surface the cap clearly on stderr as well for humans/scripts.
        print(report.error, file=sys.stderr)
        return 2
    if report.error:
        print(report.error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
