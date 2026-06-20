"""Wheel-ship-gate regression tests (autopsy-001)."""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"


@pytest.mark.ship_gate
def test_pyproject_version_matches_module_version():
    """pyproject.toml version MUST equal autopsy.__version__."""
    pkg = importlib.import_module("autopsy")
    pyproject_text = PYPROJECT.read_text()
    m = re.search(r'^version = "([^"]+)"', pyproject_text, re.MULTILINE)
    assert m is not None, "pyproject.toml has no version ="
    pyproject_version = m.group(1)
    assert pkg.__version__ == pyproject_version, (
        f"pyproject.toml version {pyproject_version!r} != autopsy.__version__ {pkg.__version__!r}"
    )


@pytest.mark.ship_gate
def test_top_level_import_is_angr_free_at_runtime():
    """``import autopsy`` MUST succeed even when angr is unreachable.

    Autopsy's engine.py does lazy angr import (inside load_project /
    AngrEngine.__init__). This test pins that contract: even if angr
    is uninstalled, ``import autopsy`` continues to work.
    """
    code = (
        "import sys, importlib;"
        "sys.modules['angr'] = None;"
        "import autopsy;"
        "print(autopsy.__version__)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"angr-free import FAILED; stderr: {result.stderr!r}"
    )
    assert result.stdout.strip() == "1.0.0"


@pytest.mark.ship_gate
def test_cli_version_is_wired():
    """``autopsy --version`` MUST print ``autopsy <version>``."""
    from autopsy.cli import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--version"])
    assert excinfo.value.code == 0


@pytest.mark.ship_gate
def test_cwe_catalog_covers_every_fixture_label():
    """Every CWE id present in ``tests/fixtures/cwe*-vuln`` filenames
    MUST be registered in autopsy.checks.CHECKS (no unregistered detectors).
    """
    import autopsy.checks as checks_mod
    from autopsy.scope import VALID_TOKENS, CWE_CATALOG

    fixture_cwes = set()
    for f in (REPO_ROOT / "tests" / "fixtures").iterdir():
        m = re.match(r"^cwe(\d+)-", f.name)
        if m:
            fixture_cwes.add(int(m.group(1)))

    registered_cwes = set(checks_mod.CHECKS.keys())

    missing = fixture_cwes - registered_cwes
    assert not missing, (
        f"Fixtures reference CWE ids {missing} not registered in "
        f"autopsy.checks.CHECKS. Add the detector or remove the fixture."
    )

    catalog_cwes = set(CWE_CATALOG.keys())
    assert catalog_cwes == registered_cwes, (
        f"CWE_CATALOG ({catalog_cwes}) != CHECKS ({registered_cwes})"
    )
    token_cwes = {int(t) for t in VALID_TOKENS if t != "all"}
    assert token_cwes == registered_cwes, (
        f"VALID_TOKENS ({token_cwes}) != CHECKS ({registered_cwes})"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """``CHANGELOG.md`` MUST exist and contain a ``## [1.0.0]`` entry.

    Pins the CHANGELOG contract against accidental deletion or future
    version-string regressions.
    """
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.exists(), "CHANGELOG.md missing at repo root"
    text = changelog.read_text()
    assert "## [1.0.0]" in text, (
        "CHANGELOG.md missing top-level '## [1.0.0]' entry"
    )
