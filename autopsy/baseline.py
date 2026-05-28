"""Finding suppression via a build-resilient baseline file.

This module is intentionally angr-free: it only computes stable fingerprints
for findings and filters a list of findings against a stored set of accepted
fingerprints. It is exercised entirely by the fast unit-test layer.

Motivation
----------
A static-analysis tool is unusable in CI/CD if every run re-fails the build on
the same already-triaged findings. The standard remedy (Semgrep's baseline,
GitHub Code Scanning's dismissed alerts, etc.) is a *baseline*: record the set
of accepted findings once, then suppress those on subsequent runs so the gate
fires only on *new* findings. Paired with ``--fail-on`` this yields the
canonical CI workflow — "fail the build only when a new vulnerability appears."

Fingerprint design
------------------
A finding's absolute ``address`` shifts on every recompile (ASLR-independent
link-time layout changes), so a baseline keyed on address would be worthless
after the next build. The fingerprint is therefore computed from the
*build-resilient* fields: the CWE id, the containing function name, and the
evidence string. These survive recompilation as long as the underlying
vulnerable pattern is unchanged, which is exactly the suppression semantics a
user wants ("I accepted *this* issue; don't re-report it").

The fingerprint is a short hex SHA-256 digest of ``"<cwe>|<function>|<evidence>"``,
stable across runs, platforms, and Python versions (text hashing only).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

# Schema version stamped into written baseline files so a future format change
# can be detected and migrated rather than silently misread.
BASELINE_VERSION = "1"

# Length of the truncated hex digest used as a fingerprint. 16 hex chars
# (64 bits) is collision-safe for the realistic finding counts autopsy emits
# while staying short enough to eyeball in a diff.
_FINGERPRINT_LEN = 16


def fingerprint(finding: Any) -> str:
    """Return a stable, build-resilient fingerprint for a finding.

    The fingerprint is derived from the CWE id, the containing function, and
    the evidence string — deliberately *excluding* the absolute address, which
    changes on every recompile. Two findings of the same CWE class, in the same
    function, with the same evidence are considered the same accepted issue.

    Args:
        finding: Any object exposing ``cwe``, ``function``, and ``evidence``
            attributes (an :class:`autopsy.report.Finding`).

    Returns:
        A 16-character lowercase hex string.
    """
    key = f"{finding.cwe}|{finding.function}|{finding.evidence}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return digest[:_FINGERPRINT_LEN]


def build_baseline(findings: Iterable[Any], binary: str | None = None) -> dict[str, Any]:
    """Build a baseline document from a collection of findings.

    Args:
        findings: The findings whose fingerprints should be recorded as
            accepted.
        binary: Optional path of the analyzed binary, recorded for human
            context. It does not affect matching.

    Returns:
        A JSON-serializable dict. Fingerprints are sorted and de-duplicated so
        the file is deterministic (stable diffs across runs).
    """
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        fp = fingerprint(f)
        # Keep the first occurrence's context; later duplicates are dropped.
        seen.setdefault(
            fp,
            {
                "fingerprint": fp,
                "cwe": f.cwe,
                "function": f.function,
                "evidence": f.evidence,
            },
        )
    return {
        "version": BASELINE_VERSION,
        "binary": binary,
        "findings": [seen[fp] for fp in sorted(seen)],
    }


def baseline_json(findings: Iterable[Any], binary: str | None = None, indent: int = 2) -> str:
    """Serialize a baseline document to a JSON string."""
    return json.dumps(build_baseline(findings, binary), indent=indent)


def load_fingerprints(text: str) -> set[str]:
    """Parse a baseline file's text into a set of accepted fingerprints.

    Tolerant of either the structured document written by :func:`build_baseline`
    (``{"version": ..., "findings": [{"fingerprint": ...}, ...]}``) or a bare
    JSON array of fingerprint strings, so a hand-maintained baseline is also
    accepted.

    Args:
        text: The raw contents of a baseline file.

    Returns:
        The set of accepted fingerprint strings.

    Raises:
        ValueError: If the text is not valid JSON or not a recognized shape.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline is not valid JSON: {exc}") from exc

    if isinstance(data, list):
        # Bare array of fingerprint strings.
        return {str(item) for item in data}

    if isinstance(data, dict):
        findings = data.get("findings", [])
        fps: set[str] = set()
        for entry in findings:
            if isinstance(entry, str):
                fps.add(entry)
            elif isinstance(entry, dict) and "fingerprint" in entry:
                fps.add(str(entry["fingerprint"]))
        return fps

    raise ValueError(
        "baseline must be a JSON object with a 'findings' array or a JSON "
        "array of fingerprint strings"
    )


def apply_baseline(findings: list[Any], accepted: set[str]) -> tuple[list[Any], int]:
    """Filter out findings whose fingerprint is in the accepted set.

    Args:
        findings: The findings produced by the analysis.
        accepted: Fingerprints to suppress (from :func:`load_fingerprints`).

    Returns:
        A tuple ``(kept, suppressed_count)`` where ``kept`` preserves the input
        order of the surviving findings and ``suppressed_count`` is how many
        were filtered out.
    """
    kept: list[Any] = []
    suppressed = 0
    for f in findings:
        if fingerprint(f) in accepted:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed
