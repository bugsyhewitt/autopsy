"""Check-selection (scope) logic.

Maps the ``--checks`` CLI argument to the concrete set of CWE check ids that
should run. angr-free and trivially unit-testable.

This module also owns the canonical CWE catalog (id -> human-readable
metadata). It is the single source of truth shared by ``--list-checks`` and
the SARIF rule generator, so the two can never drift.
"""

from __future__ import annotations

from typing import Any

# The whole-program CWE classes autopsy detects.
SUPPORTED_CWES: tuple[int, ...] = (119, 190, 338, 369, 377, 415, 416, 78, 134, 676, 787)

# Valid tokens accepted by --checks.
VALID_TOKENS: tuple[str, ...] = ("119", "190", "338", "369", "377", "415", "416", "78", "134", "676", "787", "all")

# Canonical, human-readable metadata for every CWE autopsy detects. Keyed by
# CWE id. ``name`` is the full MITRE title, ``short`` a terse label, ``uri`` the
# MITRE definition URL. Single source of truth: ``--list-checks`` renders this
# and the SARIF generator imports it for rule descriptions.
CWE_CATALOG: dict[int, dict[str, str]] = {
    78: {
        "name": "Improper Neutralization of Special Elements used in an OS Command",
        "short": "OS Command Injection",
        "uri": "https://cwe.mitre.org/data/definitions/78.html",
    },
    119: {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "short": "Buffer Overflow",
        "uri": "https://cwe.mitre.org/data/definitions/119.html",
    },
    190: {
        "name": "Integer Overflow or Wraparound",
        "short": "Integer Overflow",
        "uri": "https://cwe.mitre.org/data/definitions/190.html",
    },
    338: {
        "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "short": "Weak PRNG",
        "uri": "https://cwe.mitre.org/data/definitions/338.html",
    },
    369: {
        "name": "Divide By Zero",
        "short": "Divide By Zero",
        "uri": "https://cwe.mitre.org/data/definitions/369.html",
    },
    377: {
        "name": "Insecure Temporary File",
        "short": "Insecure Temp File",
        "uri": "https://cwe.mitre.org/data/definitions/377.html",
    },
    415: {
        "name": "Double Free",
        "short": "Double Free",
        "uri": "https://cwe.mitre.org/data/definitions/415.html",
    },
    416: {
        "name": "Use After Free",
        "short": "Use After Free",
        "uri": "https://cwe.mitre.org/data/definitions/416.html",
    },
    134: {
        "name": "Use of Externally-Controlled Format String",
        "short": "Uncontrolled Format String",
        "uri": "https://cwe.mitre.org/data/definitions/134.html",
    },
    676: {
        "name": "Use of Potentially Dangerous Function",
        "short": "Dangerous Function",
        "uri": "https://cwe.mitre.org/data/definitions/676.html",
    },
    787: {
        "name": "Out-of-bounds Write",
        "short": "Out-of-bounds Write",
        "uri": "https://cwe.mitre.org/data/definitions/787.html",
    },
}


def list_checks() -> list[dict[str, Any]]:
    """Return the catalog of available CWE detectors in canonical order.

    Each entry is a dict with ``cwe`` (int), ``token`` (str, the ``--checks``
    value that selects it), ``short`` (terse label), ``name`` (full MITRE
    title) and ``uri`` (MITRE definition URL). angr-free: callable offline with
    no binary, which is exactly what ``--list-checks`` relies on.
    """
    catalog: list[dict[str, Any]] = []
    for cwe in SUPPORTED_CWES:
        meta = CWE_CATALOG.get(
            cwe,
            {
                "name": f"CWE-{cwe}",
                "short": f"CWE-{cwe}",
                "uri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
            },
        )
        catalog.append(
            {
                "cwe": cwe,
                "token": str(cwe),
                "short": meta["short"],
                "name": meta["name"],
                "uri": meta["uri"],
            }
        )
    return catalog


def resolve_checks(token: str) -> list[int]:
    """Resolve a ``--checks`` token into an ordered list of CWE ids.

    Args:
        token: One of "119", "190", "338", "377", "415", "416", "78", "134",
            "676", "787", or "all".

    Returns:
        Ordered list of CWE ids to run. "all" expands to every supported CWE
        in canonical order.

    Raises:
        ValueError: If the token is not recognized.
    """
    if token == "all":
        return list(SUPPORTED_CWES)
    if token in {"119", "190", "338", "369", "377", "415", "416", "78", "134", "676", "787"}:
        return [int(token)]
    raise ValueError(
        f"unknown check token {token!r}; expected one of {', '.join(VALID_TOKENS)}"
    )
