# autopsy

**angr-backed, Python-native whole-program binary analysis with CWE-aligned
vulnerability detection.**

autopsy loads an ELF binary, recovers its control flow with
[angr](https://angr.io), and runs whole-program flow analysis to surface a
small set of well-defined, flow-sensitive vulnerability classes. It emits
structured JSON findings — each with the function, address, a taint trace
through the program, and human-readable evidence.

Where shallow pattern-matchers scan disassembly line-by-line, autopsy reasons
about the *whole program*: call-graph reachability, data flow from
attacker-controlled sources to dangerous sinks, and intra-procedural pointer
lifetimes. It is slower and deeper by design.

> **Scope:** ELF only. Full check coverage on x86_64; the call-site-driven
> checks (CWE-78, CWE-190) also run on AArch64. See
> [Architecture support](#architecture-support) and
> [What autopsy is not](#what-autopsy-is-not).

---

## Install

Requires **Python 3.13+**. angr is a large dependency (~hundreds of MB); the
first install takes a while.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify:

```bash
autopsy --help
autopsy --version
```

---

## Usage

```
autopsy --binary PATH [--checks {119,190,416,78,all}] [--max-states N] [--format json]
```

| Flag | Default | Meaning |
|---|---|---|
| `--binary PATH` | (required) | the ELF binary to analyze |
| `--checks` | `all` | which CWE check(s) to run |
| `--max-states N` | `1000` | angr resource cap: max cumulative symbolic states before aborting |
| `--format` | `json` | output format |

Exit codes: `0` clean run, `1` engine/load error, `2` state-limit exceeded.

### Architecture support

| Architecture | Checks that run |
|---|---|
| **x86_64 (AMD64)** | all checks (CWE-119, 190, 415, 416, 78, 787) |
| **AArch64 (ARM64)** | the call-site-driven checks: **CWE-78** and **CWE-190** |

On an AArch64 target, the register-level checks (CWE-119/415/416/787) rely on
x86_64 register conventions, so they are **skipped** rather than producing
unsound results. Skipped checks are listed in the report's `skipped_checks`
array and noted on stderr:

```bash
autopsy --binary ./arm64-target --checks all
# stderr: note: skipped CWE-119, CWE-415, CWE-416, CWE-787 (not supported on this target's architecture)
```

```json
{
  "checks": [119, 190, 415, 416, 78, 787],
  "skipped_checks": [119, 415, 416, 787],
  "findings": [ /* CWE-78 / CWE-190 findings */ ]
}
```

Other architectures and binary formats are rejected at load time with a clear
error.

The `--max-states` cap governs the symbolic reachability pass. A small value
aborts analysis with a `state limit exceeded` message; the default completes
on normal targets:

```bash
autopsy --binary ./target --checks all --max-states 10    # aborts: "state limit exceeded (>10 states)"
autopsy --binary ./target --checks all --max-states 1000  # completes
```

---

## The four CWE classes

autopsy v0.1 detects four whole-program-analysis-required vulnerability
classes. Each finding carries `cwe`, `function`, `address`, `taint_trace` (an
array of program points showing the data flow), `evidence`, and a
`confidence` triage level (`"high"` / `"medium"` / `"low"`) computed from how
specific the gathered evidence is. In SARIF output the confidence maps to
`result.level` — `high`→`error`, `medium`→`warning`, `low`→`note` — and the raw
level is preserved in `result.properties.confidence`.

### CWE-119 — buffer over-read/write via attacker-controlled offset

A memory access whose *index* is derived from attacker input, with no
preceding bounds check.

```bash
autopsy --binary tests/fixtures/cwe119-vuln --checks 119 --format json
```

```json
{
  "cwe": 119,
  "function": "store_at",
  "address": "0x401161",
  "taint_trace": [
    {"address": "0x...", "description": "attacker-controlled index introduced via atoi()"},
    {"address": "0x401161", "description": "index used in unchecked write memory access"}
  ],
  "evidence": "scaled-index memory write in store_at using an input-derived offset with no preceding bounds check",
  "confidence": "high"
}
```

### CWE-190 — integer overflow into an allocator size

A tainted value flows through 32-bit arithmetic into the size argument of
`malloc`/`calloc`/`realloc`, where it can overflow and under-allocate.

```bash
autopsy --binary tests/fixtures/cwe190-vuln --checks 190 --format json
```

```json
{
  "cwe": 190,
  "function": "alloc_records",
  "address": "0x401182",
  "taint_trace": [
    {"address": "0x...", "description": "attacker-controlled value introduced via fgets()"},
    {"address": "0x...", "description": "32-bit arithmetic (shl) computes allocation size (overflow surface)"},
    {"address": "0x401182", "description": "computed size passed to malloc()"}
  ],
  "evidence": "shl producing a 32-bit size feeds malloc() in alloc_records",
  "confidence": "medium"
}
```

### CWE-416 — use-after-free (intra-procedural)

Within one function body, a pointer is `free`d and then dereferenced, with no
function call between the free and the use.

```bash
autopsy --binary tests/fixtures/cwe416-vuln --checks 416 --format json
```

```json
{
  "cwe": 416,
  "function": "main",
  "address": "0x40117a",
  "taint_trace": [
    {"address": "0x401143", "description": "allocation via malloc()"},
    {"address": "0x401171", "description": "pointer freed via free()"},
    {"address": "0x40117a", "description": "freed pointer dereferenced (use-after-free)"}
  ],
  "evidence": "freed pointer reused in main with no intervening call (free at 0x401171, use at 0x40117a)",
  "confidence": "high"
}
```

### CWE-78 — OS command injection

Attacker-controlled input reaches a command-execution sink
(`system`/`execve`/`popen`).

```bash
autopsy --binary tests/fixtures/cwe78-vuln --checks 78 --format json
```

```json
{
  "cwe": 78,
  "function": "run_cmd",
  "address": "0x401199",
  "taint_trace": [
    {"address": "0x4011bc", "description": "attacker-controlled input read via fgets()"},
    {"address": "0x401199", "description": "tainted data reaches command sink system()"}
  ],
  "evidence": "call to system() in run_cmd with program input read via fgets()",
  "confidence": "medium"
}
```

---

## How it relates to `blight`

`autopsy` is the deep half of a complementary pair:

- **blight** — fast, shallow pattern matching over disassembly.
- **autopsy** — slow, deep whole-program flow analysis.

Run blight for breadth and speed; run autopsy for the flow-sensitive classes
that pattern matching cannot soundly find.

---

## Testing

The default test run is fast and **does not import angr** — it mocks the angr
boundary and exercises report formatting, scope logic, and CLI behavior:

```bash
pip install -e ".[dev]"
pytest                 # fast unit layer only (angr never imported)
```

The angr-backed end-to-end detection tests are marked `slow` and run against
the pre-built ELF fixtures:

```bash
pytest -m slow         # imports and runs angr against real binaries
```

Fixtures (deliberately-vulnerable binaries + a clean baseline) ship pre-built
in `tests/fixtures/`; source C files and a `Makefile` are included for
regeneration. See `tests/fixtures/REGENERATE.md`.

---

## What autopsy is not (v0.1)

- No PE binary support (ELF only).
- No architectures beyond x86_64 and AArch64 (and AArch64 runs the
  call-site-driven checks only — see [Architecture support](#architecture-support)).
- No bare-metal / firmware targets.
- No symbolic execution to PoC input generation.
- No performance optimization pass.
- No CWE classes beyond the four above.

These are deliberate v0.1 boundaries.

---

## Ethical use

autopsy is a defensive security and research tool. **Only analyze binaries you
own or are explicitly authorized to assess.** Using it against software you do
not have permission to test may be illegal. You are responsible for how you use
it.

---

## Attribution

autopsy draws design inspiration from **BinAbsInspector** (Tencent Keenlab) and
is built on the **angr** analysis engine (SecureSystemsLab). See
[`NOTICE`](NOTICE) for details.

## License

MIT — see [`LICENSE`](LICENSE).
