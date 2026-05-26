"""Shared pytest fixtures and helpers.

The fast (default) test layer never imports angr. The slow layer requires angr;
if angr is not importable, slow tests are skipped with a clear reason rather
than erroring, so the fast suite always stays green.
"""

import importlib.util
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


def _angr_available() -> bool:
    return importlib.util.find_spec("angr") is not None


@pytest.fixture(scope="session")
def require_angr():
    if not _angr_available():
        pytest.skip("angr is not installed; slow tests require angr")
