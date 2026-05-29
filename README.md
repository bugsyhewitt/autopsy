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
attacker-controlled sources to dangerous sinks, and pointer lifetimes both
within a function and across a single call hop. It is slower and deeper by
design.

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
autopsy --binary PATH [--checks {119,190,377,415,416,78,134,676,787,all}] [--max-states N]
        [--format json|sarif] [--fail-on LEVEL] [--baseline PATH] [--write-baseline PATH]
autopsy --list-checks [--format json]
```

| Flag | Default | Meaning |
|---|---|---|
| `--binary PATH` | (required) | the ELF binary to analyze (not required with `--list-checks`) |
| `--checks` | `all` | which CWE check(s) to run |
| `--max-states N` | `1000` | angr resource cap: max cumulative symbolic states before aborting |
| `--format` | `json` | output format |
| `--fail-on LEVEL` | `never` | exit non-zero (code `3`) when findings at or above this confidence are present — for CI/CD build gating |
| `--baseline PATH` | (none) | suppress findings recorded as accepted in this baseline file (build-resilient fingerprints) |
| `--write-baseline PATH` | (none) | write the current run's findings to PATH as a baseline (then exit `0`); `-` writes to stdout |
| `--list-checks` | (off) | list the available CWE detectors and exit (offline; no binary or angr needed) |

Exit codes: `0` clean run, `1` engine/load error, `2` state-limit exceeded,
`3` findings gate tripped (`--fail-on`).

### Discovering the detectors with `--list-checks`

`--list-checks` enumerates the CWE detectors autopsy ships, then exits `0`. It is
an **offline catalog query**: it never loads angr and never needs a `--binary`,
so it is safe to run anywhere (including in a container that hasn't fetched a
target yet) to discover what `--checks` tokens are available.

```bash
autopsy --list-checks
# autopsy 0.1.0 — available CWE detectors:
#
#   CWE-119  Buffer Overflow
#            --checks 119   https://cwe.mitre.org/data/definitions/119.html
#   ... (one block per detector) ...
#
# Run all detectors with --checks all (the default).
```

For tooling, `--format json` emits a machine-readable catalog — one object per
detector with its `cwe` id, the `token` to pass to `--checks`, a `short` label,
the full MITRE `name`, and the definition `uri`:

```bash
autopsy --list-checks --format json
# {
#   "checks": [
#     {
#       "cwe": 119,
#       "token": "119",
#       "short": "Buffer Overflow",
#       "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
#       "uri": "https://cwe.mitre.org/data/definitions/119.html"
#     },
#     ...
#   ]
# }
```

The catalog is the single source of truth shared with the SARIF rule
descriptions, so `--list-checks` always reflects exactly what an analysis run
can detect.

### CI/CD build gating with `--fail-on`

By default autopsy exits `0` even when it finds vulnerabilities, so the analysis
output is the signal and the exit code only reflects whether the *run* succeeded.
To make a CI/CD pipeline step fail when vulnerabilities are present, pass
`--fail-on`:

| `--fail-on` | Trips (exit `3`) when… |
|---|---|
| `never` (default) | never — findings do not change the exit code |
| `any` / `low` | any finding is present (any confidence) |
| `medium` | a `medium`- or `high`-confidence finding is present |
| `high` | a `high`-confidence finding is present |

The findings gate runs *after* error handling, so a genuine analysis failure
(`1` engine/load error or `2` state-limit) is never masked by `--fail-on`. The
output on stdout (JSON or SARIF) is unchanged; the gate only affects the exit
code and prints a one-line note to stderr.

```bash
# Fail the build only on high-confidence findings; ship JSON for the artifact.
autopsy --binary ./build/app --checks all --fail-on high --format json > autopsy.json
# stderr (when tripped): fail-on: 2 finding(s) at or above 'high' confidence
# exit code: 3
```

### Baselining: fail only on *new* findings (`--baseline`)

A static-analysis gate is unusable in CI if every run re-fails the build on the
same already-triaged findings. autopsy supports a **baseline**: record the set
of accepted findings once, then suppress those on subsequent runs so the gate
fires only on *new* findings. This is the canonical "break the build only when a
new vulnerability appears" workflow, and it pairs directly with `--fail-on`.

Findings are matched by a **build-resilient fingerprint** — a short digest of
the CWE id, the containing function, and the evidence string. The absolute
address is deliberately *excluded* because it shifts on every recompile; a
baseline keyed on address would be worthless after the next build. So once you
accept an issue, it stays suppressed across rebuilds as long as the underlying
vulnerable pattern is unchanged.

```bash
# 1. Capture the current (already-triaged) findings as the accepted baseline.
autopsy --binary ./build/app --checks all --write-baseline autopsy-baseline.json
#    -> writes autopsy-baseline.json, exits 0 (writing a baseline never breaks the build)

# 2. On every later run, suppress the accepted findings and fail only on new ones.
autopsy --binary ./build/app --checks all --baseline autopsy-baseline.json --fail-on high
#    exit 0 if no new high-confidence findings; exit 3 (build break) if a new one appears
#    stderr: note: suppressed N finding(s) via baseline autopsy-baseline.json
```

Commit `autopsy-baseline.json` to the repo. Suppressed findings are removed from
both the JSON/SARIF output and the `--fail-on` gate; the stdout report stays
machine-clean and the suppression count is noted on stderr. The baseline file is
deterministic (sorted, de-duplicated) for clean diffs, and `--baseline` also
accepts a bare JSON array of fingerprint strings for hand-maintained allowlists.
A genuine analysis failure (`1`/`2`) always takes precedence: a baseline is
never written from, nor applied to, a half-finished run.

### Architecture support

| Architecture | Checks that run |
|---|---|
| **x86_64 (AMD64)** | all checks (CWE-119, 190, 338, 369, 377, 415, 416, 78, 134, 676, 787) |
| **AArch64 (ARM64)** | the call-site-driven checks: **CWE-78**, **CWE-190**, **CWE-338**, **CWE-377** and **CWE-676** |

On an AArch64 target, the register-level checks (CWE-119/369/415/416/134/787)
rely on x86_64 register conventions, so they are **skipped** rather than
producing unsound results. Skipped checks are listed in the report's
`skipped_checks` array and noted on stderr:

```bash
autopsy --binary ./arm64-target --checks all
# stderr: note: skipped CWE-119, CWE-369, CWE-415, CWE-416, CWE-134, CWE-787 (not supported on this target's architecture)
```

```json
{
  "checks": [119, 190, 338, 369, 377, 415, 416, 78, 134, 676, 787],
  "skipped_checks": [119, 369, 415, 416, 134, 787],
  "findings": [ /* CWE-78 / CWE-190 / CWE-338 / CWE-377 / CWE-676 findings */ ]
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

## The CWE classes

autopsy detects a set of whole-program-analysis-required vulnerability
classes. Each finding carries `cwe`, `function`, `address`, `taint_trace` (an
array of program points showing the data flow), `evidence`, and a
`confidence` triage level (`"high"` / `"medium"` / `"low"`) computed from how
specific the gathered evidence is. In SARIF output the confidence maps to
`result.level` — `high`→`error`, `medium`→`warning`, `low`→`note` — and the raw
level is preserved in `result.properties.confidence`.

### SARIF output and GitHub Code Scanning

`--format sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
that is ready to upload to GitHub Code Scanning. Each result anchors to the
analyzed binary as a `physicalLocation.artifactLocation` (required by GitHub —
results without a file artifact are dropped) while still carrying the precise
sink `address.absoluteAddress`; results link their rule by `ruleIndex`; and the
`tool.driver` records `version`/`semanticVersion` so the analyzer build is
tracked. To surface findings inline on a pull request:

```bash
autopsy --binary ./target --checks all --format sarif > autopsy.sarif
gh api --method POST /repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" -f ref="refs/heads/main" \
  -f sarif="$(gzip -c autopsy.sarif | base64 -w0)"
```

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

### CWE-415 — double-free (intra-procedural and single-hop interprocedural)

The CWE-415 check runs two passes:

**Intra-procedural.** Within one function body, a pointer is `free`d and then
`free`d again, with no intervening reallocation of that pointer. Double-free is
a definitive pattern, so these findings carry `confidence: "high"`.

```bash
autopsy --binary tests/fixtures/cwe415-vuln --checks 415 --format json
```

```json
{
  "cwe": 415,
  "function": "main",
  "address": "0x40117d",
  "taint_trace": [
    {"address": "0x...", "description": "allocation via malloc()"},
    {"address": "0x...", "description": "pointer freed (first free)"},
    {"address": "0x40117d", "description": "pointer freed again (double-free)"}
  ],
  "evidence": "double-free in main: pointer freed at 0x... then freed again at 0x40117d",
  "confidence": "high"
}
```

**Single-hop interprocedural.** Double-free bugs also span a call boundary: a
caller `G` frees a pointer, then hands that same already-freed pointer to an
in-binary callee `F` that frees its argument again. autopsy detects this
single-hop pattern call-graph-driven — `F` frees its incoming parameter, and `G`
freed the pointer it passes to `F` earlier in its body with no intervening
reallocation. These cross-function findings carry `confidence: "medium"` (the
first free and the second free are both confirmed via stack-slot aliasing, but
the single-hop, parameter-based handoff is a structural match rather than a full
data-flow proof). This is distinct from the interprocedural CWE-416 pass, where
the second event is a *dereference* of the freed pointer; here the second event
is a second `free()` call. Deeper multi-hop chains are intentionally not
followed, to keep false positives at zero.

```bash
autopsy --binary tests/fixtures/cwe415-interproc-vuln --checks 415 --format json
```

```json
{
  "cwe": 415,
  "function": "run",
  "address": "0x401191",
  "taint_trace": [
    {"address": "0x401185", "description": "pointer freed in run via free()"},
    {"address": "0x401191", "description": "already-freed pointer passed to release(), which frees it again (double-free)"}
  ],
  "evidence": "single-hop cross-function double-free: run frees a pointer at 0x401185 then passes it to release() (which frees it again) at 0x401191 with no intervening reallocation",
  "confidence": "medium"
}
```

> Both CWE-415 passes use x86_64 register/stack-slot conventions and run on
> x86_64 (AMD64) targets only; on AArch64 the register-level checks are skipped.

### CWE-416 — use-after-free (intra-procedural and single-hop interprocedural)

The CWE-416 check runs two passes:

**Intra-procedural.** Within one function body, a pointer is `free`d and then
dereferenced, with no function call between the free and the use.

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

**Single-hop interprocedural.** Real-world use-after-free bugs usually span a
call boundary: a caller hands a pointer to a callee that frees it, then keeps
using the now-dangling pointer. autopsy detects this single-hop pattern — a
caller `G` passing a pointer to an in-binary callee `F` that frees its argument,
followed by a dereference of that same pointer in `G` before any other call.
These cross-function findings carry `confidence: "medium"` (the free and the use
are both confirmed via stack-slot aliasing, but the single-hop restriction makes
this a structural match rather than a full data-flow proof). Deeper multi-hop
call chains are intentionally not followed, to keep false positives at zero.

```bash
autopsy --binary tests/fixtures/cwe416-interproc-vuln --checks 416 --format json
```

```json
{
  "cwe": 416,
  "function": "run",
  "address": "0x401193",
  "taint_trace": [
    {"address": "0x40118a", "description": "pointer passed to release(), which frees it"},
    {"address": "0x401193", "description": "freed pointer dereferenced in run after release() returned (use-after-free)"}
  ],
  "evidence": "single-hop cross-function use-after-free: run passes a pointer to release() (which frees it) then dereferences it at 0x401193 with no intervening call",
  "confidence": "medium"
}
```

> Both CWE-416 passes use x86_64 register/stack-slot conventions and run on
> x86_64 (AMD64) targets only; on AArch64 the register-level checks are skipped.

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

### CWE-134 — uncontrolled (externally-controlled) format string

A printf-family call (`printf`/`fprintf`/`sprintf`/`snprintf`/`syslog` and the
`v*` variants) whose *format-string* argument is **not** a compile-time string
literal — the format register is reloaded from a stack slot (a spilled function
parameter, or a value loaded from the heap / another variable) rather than set
to a constant `.rodata` pointer. The classic pattern is `printf(user_input)`,
where the attacker controls the format string and can inject `%x`/`%n`/`%s`
specifiers to leak or corrupt memory.

A finding requires both halves of the data flow: a non-literal format sink
**and** at least one attacker-controlled input source (`fgets`/`read`/`scanf`/…)
in the program. Benign `printf("hello %s\n", name)` uses a literal format (a
`lea` rodata pointer) and is never flagged; the check holds the
zero-false-positive line on the clean baseline. Because the analysis confirms a
non-literal format register sourced from a stack slot plus a program-wide input
source — but does not prove a register-level def-use chain from the specific
read to the specific format slot — these findings carry `confidence: "medium"`.

```bash
autopsy --binary tests/fixtures/cwe134-vuln --checks 134 --format json
```

```json
{
  "cwe": 134,
  "function": "emit",
  "address": "0x401188",
  "taint_trace": [
    {"address": "0x4011ab", "description": "attacker-controlled input read via fgets()"},
    {"address": "0x401188", "description": "non-literal format string (rdi reloaded from stack slot rbp-8) reaches printf()"}
  ],
  "evidence": "printf() in emit called with a non-literal format string (format argument rdi loaded from rbp-8, not a constant) while the program reads input via fgets() — externally-controlled format string",
  "confidence": "medium"
}
```

> The CWE-134 check uses x86_64 SysV register/stack-slot conventions (the
> format argument register varies by sink: `rdi` for `printf`, `rsi` for
> `fprintf`/`sprintf`/`syslog`, `rdx` for `snprintf`) and runs on x86_64
> (AMD64) targets only; on AArch64 the register-level checks are skipped.

### CWE-787 — out-of-bounds write (heap buffer overflow)

A heap buffer is allocated (`malloc`/`calloc`/`realloc`) and then written by a
bulk-copy/fill sink (`memcpy`/`memmove`/`strncpy`/`strncat`/`memset`/`bcopy`/
`strcpy`) in the same function, where the copy length is an *independent*
value — so the write may exceed the allocation size. A finding requires the
allocator and the copy sink to be co-located in one function **and** at least
one attacker-controlled input source (`fgets`/`read`/`scanf`/…) in the program.

**Literal-length copies are excluded.** A copy whose length argument is a
compile-time immediate (e.g. `strncpy(p, line, 63)` against `malloc(64)`) has a
fixed, attacker-independent write extent and cannot produce a *tainted*
out-of-bounds write — the check resolves the sink's length-argument register
(`rdx` on x86_64 SysV) and suppresses any copy whose length is a literal. Only
copies whose length is reloaded from a stack slot or a register (i.e. possibly
tainted) are flagged. `strcpy` has no explicit length argument and is always
treated as a potential overflow sink. This is what holds the zero-false-positive
line on the clean baseline, whose only copy is a literal-length `strncpy`.

Because the analysis confirms the co-located allocator + variable-length copy +
program-wide input source — but does not symbolically prove the copy length
exceeds the allocation size on all paths — these findings carry
`confidence: "medium"`.

```bash
autopsy --binary tests/fixtures/cwe787-vuln --checks 787 --format json
```

```json
{
  "cwe": 787,
  "function": "copy_to_heap",
  "address": "0x4012ec",
  "taint_trace": [
    {"address": "0x401200", "description": "attacker-controlled value introduced via fgets()"},
    {"address": "0x401188", "description": "heap buffer allocated via malloc() — size may be tainted"},
    {"address": "0x4012ec", "description": "memcpy() writes into heap buffer with independent length — length may exceed allocation size"}
  ],
  "evidence": "malloc() allocation and memcpy() write co-located in copy_to_heap: independent tainted size and length arguments risk out-of-bounds heap write",
  "confidence": "medium"
}
```

> The CWE-787 check uses x86_64 SysV register/stack-slot conventions (the copy
> length argument is in `rdx`) and runs on x86_64 (AMD64) targets only; on
> AArch64 the register-level checks are skipped.

### CWE-676 — use of a potentially dangerous function

A call to a libc function that is inherently unsafe — one whose contract makes a
memory-safety bug the *default* outcome rather than a misuse. The canonical
example is `gets()`, which has no way to bound its write and was removed from
C11 for exactly that reason. The check flags the unbounded string family
(`strcpy`/`strcat`/`sprintf`/`vsprintf`) and the unbounded scanners
(`scanf`/`sscanf`/`fscanf`, including the glibc `__isoc99_*` aliases). Unlike
the taint-flow checks, CWE-676 needs no attacker-input source: the weakness is
the *use of the function itself*, which is how MITRE classifies CWE-676.

This is a **call-site-driven** detector — it resolves direct calls by symbol
name and never inspects registers — so it is architecture-agnostic and runs on
both x86_64 and AArch64.

`gets()` admits no safe usage at all, so a finding on it is `confidence: "high"`.
The others can in principle be used safely if the caller has already bounded
the input, so they carry `confidence: "medium"` — the call is a strong
structural red flag, not a proof of overflow. The detector deliberately does
**not** flag the bounded replacements (`strncpy`/`strncat`/`snprintf`/`fgets`/
`strlcpy`): those are the safe forms users are told to migrate to, which is what
keeps the zero-false-positive line on the clean baseline.

```bash
autopsy --binary tests/fixtures/cwe676-vuln --checks 676 --format json
```

```json
{
  "cwe": 676,
  "function": "main",
  "address": "0x401170",
  "taint_trace": [
    {"address": "0x401170", "description": "use of potentially dangerous function gets()"}
  ],
  "evidence": "call to dangerous function gets() in main: no bounds check is possible; the call always risks overflow; prefer fgets",
  "confidence": "high"
}
```

### CWE-377 — insecure temporary file

A call to a libc temporary-file function whose contract is inherently
race-prone: it generates a temporary *name* and hands it back without atomically
creating the file, leaving a time-of-check-to-time-of-use (TOCTOU) window before
the caller opens it. An attacker who wins that race can pre-create the path (often
as a symlink) and hijack the file the program believes it created. The check
flags `tmpnam`/`tmpnam_r`, `tempnam` and `mktemp`. Like CWE-676, CWE-377 needs no
attacker-input source: the weakness is the *use of the race-prone function
itself*, which is how MITRE classifies CWE-377.

This is a **call-site-driven** detector — it resolves direct calls by symbol
name and never inspects registers — so it is architecture-agnostic and runs on
both x86_64 and AArch64.

All four functions share the same structural race, so each carries
`confidence: "medium"` — the call is a definitive use of a race-prone API, but
autopsy does not prove the caller actually opens the returned path. The detector
deliberately does **not** flag the atomic create-and-open replacements
(`mkstemp`/`mkostemp`/`tmpfile`): those close the window and are the safe forms
users are told to migrate to, which is what keeps the zero-false-positive line on
the clean baseline.

```bash
autopsy --binary tests/fixtures/cwe377-vuln --checks 377 --format json
```

```json
{
  "cwe": 377,
  "function": "make_temp",
  "address": "0x401180",
  "taint_trace": [
    {"address": "0x401180", "description": "insecure temporary-file creation via tmpnam()"}
  ],
  "evidence": "call to insecure temporary-file function tmpnam() in make_temp: returns a temporary path without atomically creating the file, leaving a TOCTOU race before the caller opens it; prefer mkstemp",
  "confidence": "medium"
}
```

### CWE-338 — use of a cryptographically weak PRNG

A call to a libc random-number function whose output is *not* cryptographically
secure: a fast, statistically-uniform generator that is fully predictable to an
attacker who recovers or guesses its seed. Deriving a token, session id, nonce,
key, salt or password from such a generator is the weakness CWE-338 names. The
check flags the C standard generators `rand`/`rand_r`/`random`/`random_r`, the
BSD `drand48` family (`drand48`/`erand48`/`lrand48`/`nrand48`/`mrand48`/
`jrand48`), and the seeders that pair with them (`srand`/`srandom`/`srand48`/
`seed48`/`lcong48`) — seeding a weak PRNG, classically from `time(NULL)`, is the
canonical CWE-338 instance. Like CWE-676 and CWE-377, CWE-338 needs no
attacker-input source: the weakness is the *use of a non-CSPRNG itself*, which is
how MITRE classifies CWE-338.

This is a **call-site-driven** detector — it resolves direct calls by symbol
name and never inspects registers — so it is architecture-agnostic and runs on
both x86_64 and AArch64.

Every weak generator is a definitive non-CSPRNG, so each carries
`confidence: "medium"` — the call is a certain use of weak randomness, but
autopsy cannot prove from the binary that the output feeds a security decision
(a program may use `rand()` purely for a game or jitter). The detector
deliberately does **not** flag the secure replacements (`getrandom`,
`arc4random`/`arc4random_buf`/`arc4random_uniform`, or a read from
`/dev/urandom`): those are the forms users are told to migrate to, which is what
keeps the zero-false-positive line on the clean baseline.

```bash
autopsy --binary tests/fixtures/cwe338-vuln --checks 338 --format json
```

```json
{
  "cwe": 338,
  "function": "weak_token",
  "address": "0x4011b9",
  "taint_trace": [
    {"address": "0x4011b9", "description": "use of cryptographically weak PRNG rand()"}
  ],
  "evidence": "call to weak PRNG rand() in weak_token: rand() is a predictable non-cryptographic PRNG; its output can be reconstructed from the seed; prefer getrandom / arc4random",
  "confidence": "medium"
}
```

### CWE-369 — divide by zero

An integer division (`div`/`idiv`) whose divisor is **not** guarded by a
zero-check, in a program that reads attacker-controlled input. On x86_64 `div`
and `idiv` take a single explicit operand — the divisor — and the CPU raises a
divide-error exception (#DE, delivered as `SIGFPE`) when it is zero. If an
attacker can drive that divisor to zero — the classic `x / atoi(user_input)`
with no `if (d == 0)` check — the process crashes: the denial-of-service
weakness CWE-369 names.

The check walks each function for division instructions and **excludes** any
whose divisor register is the subject of a preceding `cmp`/`test` followed by a
conditional branch — i.e. a guard like `if (d == 0) return;`. Excluding guarded
divisions is what holds the zero-false-positive line: a program that checks its
divisor is not vulnerable and is never flagged (the `safe_ratio` companion in
the fixture is silent). An attacker-controlled input source
(`fgets`/`scanf`/`read`/`atoi`/`strtol`…) must also be present — a divisor the
program never sourced from input cannot be driven to zero by an attacker.

Findings carry `confidence: "medium"`: an unguarded divisor co-located with an
input source is a strong structural signal, but the check does not prove a
register-level def-use chain from the specific read to the divisor.

This is a **register-level** detector (it inspects the divisor operand and the
x86_64 guard instructions), so it runs on **x86_64 only** and is skipped on
AArch64.

```bash
autopsy --binary tests/fixtures/cwe369-vuln --checks 369 --format json
```

```json
{
  "cwe": 369,
  "function": "risky_ratio",
  "address": "0x401154",
  "taint_trace": [
    {"address": "0x401199", "description": "attacker-controlled value introduced via atoi()"},
    {"address": "0x401154", "description": "division with unguarded divisor dword ptr [rbp - 8] (no zero-check)"}
  ],
  "evidence": "unguarded integer division (divisor dword ptr [rbp - 8]) in risky_ratio with no zero-check; attacker input via atoi() can drive the divisor to zero (SIGFPE)",
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
- No CWE classes beyond those documented above.

These are deliberate v0.1 boundaries (the CWE class list has since grown in
Phase 2 — see [The CWE classes](#the-cwe-classes)).

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
