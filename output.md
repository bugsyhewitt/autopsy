# Worker output: ci: run angr slow tests in CI

## What was found

`addopts = "-m 'not slow'"` in `pyproject.toml` deselects all 45 angr-backed
detection tests from every pytest invocation, including CI. The existing CI job
(`test`) just runs bare `pytest`, so the slow tests have never run in CI.

angr==9.2.217 is already a **primary** dependency (not optional), so it is
installed by `pip install -e ".[dev]"` — no extra install step is required.
The fixture binaries (`tests/fixtures/cwe*-vuln`) are pre-compiled ELF files
committed to the repo, so no compile step is needed either. The `require_angr`
conftest fixture skips tests gracefully if angr is not importable, so the fast
suite always stays green regardless.

## What was changed

**`.github/workflows/ci.yml`** — added a second CI job `slow-tests`:

```yaml
slow-tests:
  runs-on: ubuntu-latest
  continue-on-error: true
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: "3.13"
    - run: pip install -e ".[dev]"
    - run: pytest -m slow -v
```

- Runs on every push and PR (same trigger as the fast job).
- `continue-on-error: true` makes it non-blocking so PR gates are not broken if
  angr has environment-specific issues on the runner.
- angr is installed as part of the normal project install — no special step.
- 45 slow tests selected (verified via `pytest --collect-only -m slow`).

`pyproject.toml` is unchanged — `addopts = "-m 'not slow'"` stays so local
`pytest` runs remain fast by default; developers use `pytest -m slow` explicitly
when they want to run angr tests.
