"""Command-line interface for autopsy.

angr-free at import time: the heavy engine is only constructed when a real
analysis runs (inside :func:`autopsy.analyzer.analyze`). Parsing ``--help`` and
arguments never touches angr.
"""

from __future__ import annotations

import argparse
import json
import sys

from autopsy import __version__
from autopsy.scope import VALID_TOKENS, list_checks

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
    # --binary is required for analysis but NOT for --list-checks (which is an
    # offline catalog query). argparse can't express "required unless other
    # flag", so it's validated manually in main() after parsing.
    parser.add_argument(
        "--binary",
        metavar="PATH",
        help="path to the target ELF binary to analyze (required unless --list-checks)",
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
        "--baseline",
        metavar="PATH",
        help=(
            "suppress findings recorded as accepted in this baseline file "
            "(build-resilient fingerprints). Pair with --fail-on to break the "
            "build only on NEW findings. Suppressed findings are removed from "
            "the JSON/SARIF output and from the --fail-on gate"
        ),
    )
    parser.add_argument(
        "--write-baseline",
        metavar="PATH",
        help=(
            "write the current run's findings to PATH as a baseline file (then "
            "exit 0 without applying --fail-on), so future runs can suppress "
            "them with --baseline. '-' writes the baseline to stdout"
        ),
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help=(
            "list the available CWE detectors and exit (offline; no --binary "
            "required). Honors --format: text (default) or json for tooling"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"autopsy {__version__}",
    )
    return parser


def _render_list_checks(fmt: str) -> str:
    """Render the CWE detector catalog as text or JSON.

    ``json`` emits ``{"checks": [...]}`` (each entry carries cwe/token/short/
    name/uri) for pipeline consumption. ``text`` (and any non-json value) emits
    a human-readable table. angr-free: drives entirely off the static catalog.
    """
    checks = list_checks()
    if fmt == "json":
        return json.dumps({"checks": checks}, indent=2)
    lines = [f"autopsy {__version__} — available CWE detectors:", ""]
    for c in checks:
        # token is the value to pass to --checks; left-pad so the column aligns.
        lines.append(f"  CWE-{c['cwe']:<3}  {c['short']}")
        lines.append(f"           --checks {c['token']}   {c['uri']}")
    lines.append("")
    lines.append("Run all detectors with --checks all (the default).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --list-checks is an offline catalog query: handle it before requiring a
    # binary and before importing the (angr-backed) analyzer, so it stays fast
    # and works with no target. It defaults to human-readable text; --format
    # json is honored only when the user explicitly asks for it (the analysis
    # path's json default must not silently force JSON onto the catalog).
    if args.list_checks:
        argv_tokens = sys.argv[1:] if argv is None else argv
        explicit_format = "--format" in argv_tokens or any(
            t.startswith("--format=") for t in argv_tokens
        )
        fmt = args.format if explicit_format else "text"
        print(_render_list_checks(fmt))
        return 0

    # --binary is required for any analysis run. argparse can't express
    # "required unless --list-checks", so enforce it here.
    if not args.binary:
        parser.error("--binary is required (or use --list-checks)")

    # Import the driver lazily so --help stays angr-free and instant.
    from autopsy.analyzer import analyze

    report = analyze(
        binary=args.binary,
        checks_token=args.checks,
        max_states=args.max_states,
    )

    # Baseline generation: snapshot the current findings as the accepted set,
    # then exit cleanly. This runs before --baseline suppression (you record the
    # full current state) and before the --fail-on gate (writing a baseline must
    # never break a build). A genuine analysis failure still takes precedence so
    # we don't persist a baseline built from a half-finished run.
    if args.write_baseline and not (report.state_limit_exceeded or report.error):
        from autopsy.baseline import baseline_json

        doc = baseline_json(report.findings, binary=report.binary)
        if args.write_baseline == "-":
            print(doc)
        else:
            try:
                with open(args.write_baseline, "w", encoding="utf-8") as fh:
                    fh.write(doc + "\n")
            except OSError as exc:
                print(f"error: cannot write baseline: {exc}", file=sys.stderr)
                return 1
            print(
                f"wrote baseline ({len(report.findings)} finding(s)) to "
                f"{args.write_baseline}",
                file=sys.stderr,
            )
        return 0

    # Baseline suppression: drop findings whose build-resilient fingerprint is
    # recorded as accepted. Applied before output and before the --fail-on gate
    # so suppressed findings affect neither the report nor the exit code.
    suppressed = 0
    if args.baseline and not (report.state_limit_exceeded or report.error):
        from autopsy.baseline import apply_baseline, load_fingerprints

        try:
            with open(args.baseline, encoding="utf-8") as fh:
                accepted = load_fingerprints(fh.read())
        except OSError as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        report.findings, suppressed = apply_baseline(report.findings, accepted)

    if args.format == "json":
        print(report.to_json())
    elif args.format == "sarif":
        from autopsy.sarif import to_sarif_json
        print(to_sarif_json(report))

    if suppressed:
        # Keep stdout machine-clean; note the suppression count on stderr so a
        # human/script can see the baseline did something.
        print(
            f"note: suppressed {suppressed} finding(s) via baseline {args.baseline}",
            file=sys.stderr,
        )

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
