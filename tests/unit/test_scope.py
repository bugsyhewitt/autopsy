"""Fast unit tests for check-selection (scope) logic. angr-free."""

import pytest

from autopsy.scope import (
    CWE_CATALOG,
    list_checks,
    resolve_checks,
    SUPPORTED_CWES,
    VALID_TOKENS,
)


@pytest.mark.parametrize(
    "token,expected",
    [
        ("119", [119]),
        ("190", [190]),
        ("415", [415]),
        ("416", [416]),
        ("78", [78]),
        ("134", [134]),
        ("676", [676]),
        ("787", [787]),
        ("all", [119, 190, 415, 416, 78, 134, 676, 787]),
    ],
)
def test_resolve_checks_valid_tokens(token, expected):
    assert resolve_checks(token) == expected


def test_all_expands_to_every_supported_cwe():
    assert resolve_checks("all") == list(SUPPORTED_CWES)


def test_unknown_token_raises():
    with pytest.raises(ValueError):
        resolve_checks("999")


def test_valid_tokens_constant_complete():
    assert set(VALID_TOKENS) == {"119", "190", "415", "416", "78", "134", "676", "787", "all"}


# --- CWE catalog / list_checks --------------------------------------------


def test_catalog_covers_every_supported_cwe():
    # Every detector we run must have human-readable metadata.
    assert set(CWE_CATALOG) == set(SUPPORTED_CWES)


def test_list_checks_is_canonical_order():
    cwes = [c["cwe"] for c in list_checks()]
    assert cwes == list(SUPPORTED_CWES)


def test_list_checks_entry_shape():
    for entry in list_checks():
        assert set(entry) == {"cwe", "token", "short", "name", "uri"}
        assert entry["token"] == str(entry["cwe"])
        assert entry["uri"].endswith(f"/{entry['cwe']}.html")
        # Each token must be a real --checks selector.
        assert entry["token"] in VALID_TOKENS


def test_sarif_meta_is_the_same_catalog():
    # The SARIF generator must share the single source of truth, not a copy.
    from autopsy import sarif

    assert sarif._CWE_META is CWE_CATALOG
