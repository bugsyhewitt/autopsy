"""SARIF 2.1.0 output emitter for autopsy.

Converts an :class:`autopsy.report.Report` to a SARIF 2.1.0-compliant dict
suitable for JSON serialization.  No new dependencies: SARIF is pure JSON.

SARIF specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

Mapping:
  * One ``run`` per analysis invocation (one binary).
  * ``tool.driver.rules`` — one rule entry per CWE check that was requested.
  * ``results`` — one entry per ``Finding``.
  * ``locations[].physicalLocation.address.absoluteAddress`` — binary address.
  * ``relatedLocations`` — taint trace program points.
  * CWE ids appear in ``result.taxa`` under the MITRE CWE taxonomy.

Usage::

    from autopsy.sarif import to_sarif
    import json
    sarif_dict = to_sarif(report)
    print(json.dumps(sarif_dict, indent=2))
"""

from __future__ import annotations

import json
from typing import Any

from autopsy import __version__ as _AUTOPSY_VERSION
from autopsy.report import Report

# Canonical CWE catalog lives in :mod:`autopsy.scope` (single source of truth
# shared with ``--list-checks``); aliased here so local references are unchanged.
from autopsy.scope import CWE_CATALOG as _CWE_META

# SARIF 2.1.0 schema URI (informational; not fetched at runtime).
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# MITRE CWE taxonomy definition for SARIF taxa references.
_CWE_TAXONOMY_GUID = "FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5"
_CWE_TAXONOMY = {
    "name": "CWE",
    "version": "4.14",
    "organization": "MITRE",
    "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
    "informationUri": "https://cwe.mitre.org/",
    "guid": _CWE_TAXONOMY_GUID,
    "isComprehensive": False,
}

def _rule_for_cwe(cwe: int) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` (rule) entry for a CWE id."""
    meta = _CWE_META.get(cwe, {
        "name": f"CWE-{cwe}",
        "short": f"CWE-{cwe}",
        "uri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
    })
    return {
        "id": f"CWE-{cwe}",
        "name": meta["short"].replace(" ", ""),
        "shortDescription": {"text": meta["short"]},
        "fullDescription": {"text": meta["name"]},
        "helpUri": meta["uri"],
        "relationships": [
            {
                "target": {
                    "id": str(cwe),
                    "guid": _CWE_TAXONOMY_GUID,
                    "toolComponent": {"name": "CWE", "guid": _CWE_TAXONOMY_GUID},
                },
                "kinds": ["superset"],
            }
        ],
    }


# Map autopsy's three-level confidence onto SARIF result severity levels.
# high -> error, medium -> warning, low -> note (SARIF 2.1.0 result.level enum).
_CONFIDENCE_TO_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _result_for_finding(
    finding,
    binary_uri: str,
    rule_index: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build a SARIF ``result`` entry for a single Finding.

    Args:
        finding: The :class:`~autopsy.report.Finding` to convert.
        binary_uri: The analyzed artifact's URI (the binary path). GitHub Code
            Scanning rejects any result that lacks a
            ``physicalLocation.artifactLocation`` referencing a file, so every
            result anchors to the analyzed binary here in addition to carrying
            the precise binary ``address``.
        rule_index: Maps each ``CWE-N`` rule id to its 0-based position in
            ``tool.driver.rules``. When supplied, the result links its rule via
            ``ruleIndex`` (SARIF best practice for reliable rule resolution by
            consumers like GitHub Code Scanning).
    """
    address_int = finding.address
    confidence = getattr(finding, "confidence", "medium")
    level = _CONFIDENCE_TO_LEVEL.get(confidence, "warning")
    rule_id = f"CWE-{finding.cwe}"

    # Primary location: anchor to the analyzed binary as an artifact (required
    # by GitHub Code Scanning) and carry the precise sink address alongside it.
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": binary_uri},
            "address": {
                "absoluteAddress": address_int,
            },
        },
        "logicalLocations": [
            {
                "name": finding.function,
                "kind": "function",
            }
        ],
    }

    # Taint trace becomes relatedLocations.
    related: list[dict[str, Any]] = []
    for i, tp in enumerate(finding.taint_trace):
        related.append({
            "id": i,
            "message": {"text": tp.description},
            "physicalLocation": {
                "address": {
                    "absoluteAddress": tp.address,
                }
            },
        })

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": finding.evidence},
        "locations": [location],
        # SARIF property bag carries the raw triage confidence for consumers
        # that prefer the original three-level scheme over the SARIF level.
        "properties": {"confidence": confidence},
        "taxa": [
            {
                "id": str(finding.cwe),
                "guid": _CWE_TAXONOMY_GUID,
                "toolComponent": {"name": "CWE", "guid": _CWE_TAXONOMY_GUID},
            }
        ],
    }
    if related:
        result["relatedLocations"] = related

    # Link the result to its rule by index when the index map is available.
    if rule_index is not None and rule_id in rule_index:
        result["ruleIndex"] = rule_index[rule_id]

    return result


def to_sarif(report: Report) -> dict[str, Any]:
    """Convert an autopsy :class:`~autopsy.report.Report` to a SARIF 2.1.0 dict.

    Args:
        report: The completed analysis report.

    Returns:
        A dict conforming to the SARIF 2.1.0 schema, ready for
        ``json.dumps()``.
    """
    # Collect the unique CWE ids present in findings for rule generation.
    # Always include at least one rule per requested check so the tool
    # descriptor is informative even on zero findings.
    rule_cwes: set[int] = set(report.checks)
    for f in report.findings:
        rule_cwes.add(f.cwe)
    rules = [_rule_for_cwe(cwe) for cwe in sorted(rule_cwes)]

    # 0-based rule-id -> position map so each result can link its rule by index
    # (SARIF best practice; GitHub Code Scanning resolves rules reliably this way).
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}

    results = [
        _result_for_finding(f, report.binary, rule_index) for f in report.findings
    ]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "autopsy",
                "informationUri": "https://github.com/bugsyhewitt/autopsy",
                # version/semanticVersion let GitHub Code Scanning and other
                # consumers track which analyzer build produced the results.
                "version": _AUTOPSY_VERSION,
                "semanticVersion": _AUTOPSY_VERSION,
                "rules": rules,
            }
        },
        "artifacts": [
            {
                "location": {"uri": report.binary},
                "roles": ["analysisTarget"],
            }
        ],
        "results": results,
    }

    if report.error:
        run["invocations"] = [
            {
                "executionSuccessful": False,
                "toolExecutionNotifications": [
                    {
                        "message": {"text": report.error},
                        "level": "error",
                    }
                ],
            }
        ]
    else:
        run["invocations"] = [{"executionSuccessful": True}]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
        "taxonomies": [_CWE_TAXONOMY],
    }


def to_sarif_json(report: Report, indent: int = 2) -> str:
    """Serialize an autopsy Report as a SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(report), indent=indent)
