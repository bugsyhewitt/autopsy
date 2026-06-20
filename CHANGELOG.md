# Changelog

All notable changes to autopsy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added

- 21 CWE detector modules covering 19 unique CWEs (CWE-22, CWE-78, CWE-119, CWE-125,
  CWE-134, CWE-190, CWE-327, CWE-338, CWE-362, CWE-367, CWE-369, CWE-377, CWE-401,
  CWE-415, CWE-416, CWE-476, CWE-676, CWE-732, CWE-787) plus 2 interprocedural
  extensions (CWE-415 interproc, CWE-416 interproc) shipped across PRs #34–#39.
- AArch64 support for single-hop interprocedural CWE-415 / CWE-416 detection (PR #38).
- CWE-78 expanded sinks: `execvpe`, `posix_spawn`, `posix_spawnp`, `wordexp` (PR #39).
- CWE-327 broken/risky cryptographic algorithm detector (PR #37).
- CWE-22 path-traversal detector (PR #36).
- Wheel-ship-gate contract: `tests/test_wheel_ship_gate.py` regression suite
  (build + fresh-venv install + end-to-end + version-source-of-truth + CHANGELOG
  existence) with `ship_gate` pytest marker registration (PR #40, this release).
- CHANGELOG.md itself (this file).

### Notes

- Python 3.13+ required; angr==9.2.217 pinned.
- v0.1.0 was the initial pre-release at HEAD 2ce6caf; v1.0.0 is the first production release.
- Ship-gate command: `pytest -m ship_gate` (5 tests: 4 PR-#40-shipped + 1 CHANGELOG pin test).
- 615 fast tests pass; 45 slow (angr-backed) tests deselected by default
  (`addopts = "-m 'not slow'"`).
