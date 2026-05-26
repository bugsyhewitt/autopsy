"""Check-selection (scope) logic.

Maps the ``--checks`` CLI argument to the concrete set of CWE check ids that
should run. angr-free and trivially unit-testable.
"""

from __future__ import annotations

# The four whole-program CWE classes autopsy detects in v0.1.
SUPPORTED_CWES: tuple[int, ...] = (119, 190, 416, 78)

# Valid tokens accepted by --checks.
VALID_TOKENS: tuple[str, ...] = ("119", "190", "416", "78", "all")


def resolve_checks(token: str) -> list[int]:
    """Resolve a ``--checks`` token into an ordered list of CWE ids.

    Args:
        token: One of "119", "190", "416", "78", or "all".

    Returns:
        Ordered list of CWE ids to run. "all" expands to every supported CWE
        in canonical order.

    Raises:
        ValueError: If the token is not recognized.
    """
    if token == "all":
        return list(SUPPORTED_CWES)
    if token in {"119", "190", "416", "78"}:
        return [int(token)]
    raise ValueError(
        f"unknown check token {token!r}; expected one of {', '.join(VALID_TOKENS)}"
    )
