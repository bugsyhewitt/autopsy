"""Fast unit tests for check-selection (scope) logic. angr-free."""

import pytest

from autopsy.scope import resolve_checks, SUPPORTED_CWES, VALID_TOKENS


@pytest.mark.parametrize(
    "token,expected",
    [
        ("119", [119]),
        ("190", [190]),
        ("416", [416]),
        ("78", [78]),
        ("all", [119, 190, 416, 78]),
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
    assert set(VALID_TOKENS) == {"119", "190", "416", "78", "all"}
