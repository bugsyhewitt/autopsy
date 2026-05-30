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

> **Scope:** ELF only. Full check coverage on x86_64; every check (the
> call-site-driven CWE-78/338/362/367/377/676 plus the arch-aware register-level
> CWE-732, CWE-190, CWE-134, CWE-401, CWE-415, CWE-416, CWE-369, CWE-119,
> CWE-787, CWE-125, CWE-476) also runs on AArch64. See
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
autopsy --binary PATH [--checks {119,125,190,338,362,367,369,377,401,415,416,78,134,676,732,787,all}] [--max-states N]
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
| **x86_64 (AMD64)** | all checks (CWE-119, 125, 190, 338, 362, 367, 369, 377, 401, 415, 416, 476, 78, 134, 676, 732, 787) |
| **AArch64 (ARM64)** | all checks — the call-site-driven checks (**CWE-78**, **CWE-125**, **CWE-338**, **CWE-362**, **CWE-367**, **CWE-377**, **CWE-676**) plus the arch-aware register-level checks (**CWE-732**, **CWE-190**, **CWE-134**, **CWE-401**, **CWE-415**, **CWE-416**, **CWE-369**, **CWE-119**, **CWE-787**, **CWE-476**) |

On an AArch64 target, the **CWE-732** permission check runs natively: its register
reasoning only reads a single mode/mask *immediate* out of the AAPCS64 argument
register (`w1` for `chmod`, `w0` for `umask`, including the `mov w0, wzr`
zero-register encoding of `umask(0)`), so it is arch-aware rather than
x86_64-bound. The **CWE-190** integer-overflow check is likewise arch-aware: it
inspects the 32-bit size-arithmetic register before the allocator call, and the
engine knows both the x86_64 forms (`imul`/`shl` over `e**`/`r**d`) and the
AArch64 forms (`mul`/`lsl` over `w0..w30` — e.g. `count * 4096` lowers to
`lsl w8, w8, #0xc`), so it runs on AArch64 too. The **CWE-134** uncontrolled-
format-string check is arch-aware too: it reads the printf-family *format-string*
argument out of the AAPCS64 register (`x0` for `printf`, `x1` for
`fprintf`/`sprintf`/`syslog`, `x2` for `snprintf`) and recognizes both the x86_64
rodata-literal form (`lea reg, [rip+disp]`) and the AArch64 one (`adrp`/`adr`); a
stack-slot reload (`ldr x0, [sp, #N]`) is the non-literal/attacker-controlled
format, so it runs on AArch64 too. The **CWE-415** intra-procedural double-free
check is arch-aware as well: it tracks the allocator return register into a
stack slot and the first-argument register handed to two successive `free`
calls, and the scanner knows both the x86_64 form (`rax`/`rdi`; `mov` slot
store/reload over `[rbp-N]`/`[rsp-N]`) and the AArch64 one (`x0`; `str`/`ldr`
over `[sp,#N]`/`[x29,#N]`), so it runs on AArch64 too. (Its single-hop
interprocedural companion pass remains x86_64-only and simply reports nothing on
AArch64.) The **CWE-416** intra-procedural use-after-free check is arch-aware as
well: it reuses the same allocation/free/stack-slot-aliasing machinery as
CWE-415 but, after the `free`, watches for the freed pointer to be reloaded from
its slot and **dereferenced** through that base register (with no intervening
call); the scanner knows both the x86_64 form (`rax`/`rdi`; `mov` slot
store/reload over `[rbp-N]`/`[rsp-N]`; deref `[rax]`) and the AArch64 one (`x0`;
`str`/`ldr` over `[sp,#N]`/`[x29,#N]`; deref `[x9]`), so it runs on AArch64 too.
(Its single-hop interprocedural companion pass remains x86_64-only and reports
nothing on AArch64.) The **CWE-369** divide-by-zero check is arch-aware as well: it locates
a division whose divisor is not guarded by a preceding zero-check, and the engine
knows both the x86_64 form (`div`/`idiv` single divisor operand; guard via
`cmp`/`test` + a conditional jump) and the AArch64 one (`sdiv`/`udiv` third
operand; guard via `cbz`/`cbnz` on the divisor, or `cmp`/`tst` + `b.<cond>`), so
it runs on AArch64 too. (ARMv8 defines divide-by-zero as `0` rather than a trap,
so the AArch64 consequence is a silently-wrong result an attacker can force, not
a SIGFPE — but the unguarded divisor is still the weakness.) The **CWE-119**
buffer over-read/write check is arch-aware as well: it locates a scaled-index
memory access whose register index is derived from a sign/zero-extended int (the
`arr[i]` index-promotion idiom) and that is **not** preceded by a bounds-check
compare/branch, and the engine knows both the x86_64 form (a scaled-index memory
operand `[base+index]` preceded by `movsxd`/`cdqe`; guard via `cmp` + a
conditional jump) and the AArch64 one (the index sign-extended with
`ldrsw x10, [sp, #N]` or `sxtw`, the address formed with an explicit base+index
sum `add x9, x9, x10`, the dereference through that base register `strb w8, [x9]`;
guard via `cmp`/`subs`/`tst`/`tbz`/`tbnz`/`cbz`/`cbnz` + `b.<cond>`), so it runs
on AArch64 too (the `tests/fixtures/cwe119-aarch64-vuln` ARM64 fixture exercises
it). The **CWE-787** heap out-of-bounds write check is arch-aware too: its
allocator/source/copy call-site discovery is already arch-agnostic, and the
literal-length suppression helper (`copy_call_length_is_literal`) now reads
the AAPCS64 length-argument register (`x2`/`w2`) for `memcpy`/`memmove`/
`memset`/`strncpy`/`strncat`/`bcopy` — a compile-time `mov w2, #imm` (or the
`mov w2, wzr` zero-register form) is treated as a literal length (and the
copy site is suppressed), while a stack-slot reload (`ldr w2, [sp, #N]` /
`ldursw`) is treated as a possibly-tainted runtime length (the copy site
fires), so it runs on AArch64 too (the `tests/fixtures/cwe787-aarch64-vuln`
ARM64 fixture exercises both sides). The **CWE-476** NULL-pointer-dereference
check is arch-aware as well: it locates the spill of the allocator's return
register into a stack slot, follows alias propagation through slot reloads and
register-to-register copies, and reports the first dereference through an
aliasing register unless a NULL-check guard intervenes; the engine knows both
the x86_64 form (`rax` return; `mov [rbp-N], rax` spill; `test reg, reg` /
`cmp reg, 0` + conditional-jump guard) and the AArch64 one (`x0` return;
`str x0, [sp,#N]` / `[x29,#N]` spill; `cbz` / `cbnz` on a slot-aliased
register, or `cmp xR, #0` / `cmp xR, xzr` / `tst xR, xR` + `b.<cond>` guard),
so it runs on AArch64 too (the `tests/fixtures/cwe476-aarch64-vuln` ARM64
fixture exercises both sides). With CWE-476 ported, **every** register-level
check is arch-aware and nothing is skipped on AArch64. The report's
`skipped_checks` array is empty on a supported architecture:

```json
{
  "checks": [119, 125, 190, 338, 362, 367, 369, 377, 401, 415, 416, 476, 78, 134, 676, 732, 787],
  "skipped_checks": [],
  "findings": [ /* CWE-78 / 119 / 134 / 190 / 338 / 362 / 367 / 369 / 377 / 415 / 416 / 476 / 676 / 732 / 787 findings */ ]
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

**Stable alert tracking across builds.** Every result carries a
`partialFingerprints` entry under the key `autopsy/finding/v1`. GitHub Code
Scanning uses `partialFingerprints` to recognize the same alert from one run to
the next and de-duplicate it. This matters specifically for binary analysis:
autopsy's locations are binary addresses, and those shift on every recompile, so
without a stable fingerprint GitHub would close and re-open the *same*
vulnerability as a brand-new alert on each commit (alert churn). The fingerprint
is the build-resilient `CWE | function | evidence` digest — the *same* identity
the `--baseline` feature uses to suppress accepted findings, so SARIF cross-run
tracking and baseline suppression always agree on what counts as "the same
finding."

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

> This is an **arch-aware register-level** detector: it locates a scaled-index
> memory access whose register index is derived from a sign/zero-extended int
> and that is not guarded by a preceding bounds-check compare/branch. The engine
> knows both the x86_64 forms (a scaled-index operand `[base+index]` preceded by
> `movsxd`/`cdqe`; guard via `cmp`) and the AArch64 forms (the index
> sign-extended with `ldrsw`/`sxtw`, the address formed with an explicit
> base+index sum `add xD, xBase, xIdx`, the dereference through `[xD]`; guard via
> `cmp`/`subs`/`tst`/`tbz`/`tbnz`/`cbz`/`cbnz` + `b.<cond>`), so — like
> CWE-732/190/134/415/416/369 — it runs on **both x86_64 and AArch64** (the
> `tests/fixtures/cwe119-aarch64-vuln` ARM64 fixture exercises it). A
> bounds-checked access is the clean-baseline pattern and is never flagged.

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

This is an **arch-aware register-level** detector: it inspects the 32-bit
size-arithmetic register feeding the allocator call. The engine knows both the
x86_64 forms (`imul`/`mul`/`add`/`shl`/`sal`/`lea` over the `e**`/`r**d` views)
and the AArch64 forms (`mul`/`madd`/`add`/`lsl` over `w0..w30` — e.g.
`count * 4096` lowers to `lsl w8, w8, #0xc`, `count * width` to `mul w8, w8, w9`),
so — like CWE-732 — it runs on **both x86_64 and AArch64** (the
`tests/fixtures/cwe190-aarch64-vuln` ARM64 fixture exercises it). An op that
combines two distinct register sources (both potentially tainted) is reported
`high`; a register-plus-immediate op (one symbolic operand) is `medium`.

### CWE-401 — memory leak (missing release of an owned allocation)

A function calls an *owned* allocator (`malloc`/`calloc`/`realloc`/
`reallocarray`/`strdup`/`strndup`) and then returns without releasing or
transferring the allocation. The detector flags a leak only when **all four**
ownership-transfer paths are absent before the function returns:

- no `free()`/`realloc()`/`reallocarray()` call whose first argument aliases
  the slot (the slot is never released here),
- no reload of the slot into the architecture's return register (`rax` on
  x86_64, `x0` on AArch64) before a `ret` (the pointer is not returned),
- no reload of the slot into any integer argument register before any other
  call (the pointer is not handed to a callee that might take ownership), and
- no store of an aliasing register to a memory location other than the
  original spill slot (the pointer is not stashed in a struct field, a global,
  or another stack frame).

If any of those four escapes appears the function is treated as transferring
ownership and the site stays silent. The canonical
`p = malloc(64); use(p); free(p);` is silent (a release call clears the
finding), and the canonical `char *make(void){ return malloc(64); }` is
silent (a return-register escape clears the finding) — only an allocation
with *none* of the four escapes is reported.

`getenv` and `secure_getenv` are deliberately **excluded** from the owned
allocator set: their return values point at process-environment storage
owned by libc and must not be freed by the caller, so an unfreed `getenv()`
result is not a leak. (CWE-476 still tracks `getenv()` results for unchecked
dereferences — a different weakness.)

```bash
autopsy --binary tests/fixtures/cwe401-vuln --checks 401 --format json
```

```json
{
  "cwe": 401,
  "function": "leaky",
  "address": "0x401143",
  "taint_trace": [
    {"address": "0x401143", "description": "heap allocation via malloc() — caller owns the returned pointer"},
    {"address": "0x401143", "description": "the allocator result is spilled to stack slot rbp-8 and never released or transferred before the function returns"}
  ],
  "evidence": "malloc() in leaky returns an owned heap pointer that is never freed and never escapes the function (no free()/realloc(), no return, no argument-pass, no memory store) — the allocation leaks when the function exits",
  "confidence": "medium"
}
```

> This is an **arch-aware register-level** detector. The slot-tracking
> abstraction is identical across architectures — only the concrete register
> names (`rax`/`rdi`-`r9` on x86_64 SysV; `x0`/`x0`-`x7` on AAPCS64), the
> spill/reload mnemonics, and the stack-slot operand syntax differ. So — like
> CWE-415/416/476 — it runs on **both x86_64 and AArch64**. Findings carry
> `confidence: "medium"`: an owned allocator with no observed release or
> escape is a strong structural leak signal, but the intra-procedural slot
> tracking is not a full ownership proof (an alias path the scanner does not
> recognize could legitimately transfer ownership without being visible). The
> detector is deliberately intra-procedural — every escape suppresses the
> finding, which is the right trade for autopsy's "tight signal" posture.

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

> The **intra-procedural** pass is **arch-aware: it runs on both x86_64 and
> AArch64.** The scanner tracks the allocator return register and the
> first-argument register handed to two successive `free` calls, and knows both
> the x86_64 form (`rax`/`rdi`; `mov` slot store/reload over
> `[rbp-N]`/`[rsp-N]`) and the AArch64 one (`x0`; `str`/`ldr` over
> `[sp,#N]`/`[x29,#N]`); the `tests/fixtures/cwe415-aarch64-vuln` ARM64 fixture
> exercises it. The **single-hop interprocedural** pass still uses x86_64
> register/stack-slot conventions and runs on x86_64 (AMD64) targets only; on
> AArch64 it simply reports nothing.

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

> The **intra-procedural** pass is arch-aware and runs on both x86_64 (AMD64)
> and AArch64 (ARM64): it tracks the allocator return register into a stack slot
> and the freed pointer's later dereference, knowing both the x86_64 form
> (`rax`/`rdi`; `mov` slot store/reload over `[rbp-N]`/`[rsp-N]`; deref `[rax]`)
> and the AArch64 one (`x0`; `str`/`ldr` over `[sp,#N]`/`[x29,#N]`; deref `[x9]`).
> The **single-hop interprocedural** pass still uses x86_64-only SysV
> first-argument/stack-slot conventions and reports nothing on AArch64.

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

> This is an **arch-aware register-level** detector. The format-argument
> register varies by sink and architecture — SysV/x86_64 (`rdi` for `printf`,
> `rsi` for `fprintf`/`sprintf`/`syslog`, `rdx` for `snprintf`) and AAPCS64/
> AArch64 (`x0`/`x1`/`x2` at the same parameter positions) — and the engine
> recognizes both the x86_64 rodata-literal form (`lea reg, [rip+disp]`) and the
> AArch64 one (`adrp`/`adr`), with a stack-slot reload (`mov reg, [rbp-N]` on
> x86_64, `ldr xN, [sp, #N]` on AArch64) marking the non-literal format. So —
> like CWE-732 and CWE-190 — it runs on **both x86_64 and AArch64** (the
> `tests/fixtures/cwe134-aarch64-vuln` ARM64 fixture exercises it). It is *not*
> skipped on AArch64.

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

### CWE-125 — out-of-bounds read (heap buffer over-read)

The read-side complement of CWE-787. A heap buffer is allocated
(`malloc`/`calloc`/`realloc`) and then read by a bulk-compare/scan sink
(`memcmp`/`strncmp`/`strncasecmp`/`memchr`) in the same function, where the
read length is an *independent* value — so the read may walk past the
allocation. A finding requires the allocator and the read sink to be co-located
in one function **and** at least one attacker-controlled input source
(`fgets`/`read`/`scanf`/…) in the program.

**Literal-length reads are excluded** — a `memcmp(buf, magic, 4)` whose length
is a compile-time immediate cannot be tainted and is not flagged, mirroring the
CWE-787 suppression. The length argument lives in the same SysV/AAPCS64
register as the write-side sinks (`rdx`/`x2`), so the suppression engine
generalizes transparently across `memcmp`/`strncmp`/`strncasecmp`/`memchr`.

Because the analysis confirms the co-located allocator + variable-length read +
program-wide input source — but does not symbolically prove the read length
exceeds the allocation size on all paths — these findings carry
`confidence: "medium"`. CWE-125 sits at rank #6 on the 2025 MITRE/CISA CWE Top
25 with 12 CISA KEV entries (actively exploited), so this is one of the
highest-leverage detectors autopsy ships.

```bash
autopsy --binary tests/fixtures/cwe125-vuln --checks 125 --format json
```

```json
{
  "cwe": 125,
  "function": "compare_from_heap",
  "address": "0x4012ec",
  "taint_trace": [
    {"address": "0x401200", "description": "attacker-controlled value introduced via fgets()"},
    {"address": "0x401188", "description": "heap buffer allocated via malloc() — size may be tainted"},
    {"address": "0x4012ec", "description": "memcmp() reads from heap buffer with independent length — length may exceed allocation size"}
  ],
  "evidence": "malloc() allocation and memcmp() read co-located in compare_from_heap: independent tainted size and length arguments risk out-of-bounds heap read",
  "confidence": "medium"
}
```

> CWE-125 is purely call-site-driven (it consults `call_sites_to` to find
> allocator and read sinks, and the engine's existing arch-aware
> length-literal helper for suppression). It runs on both x86_64 and AArch64.

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

An integer division whose divisor is **not** guarded by a zero-check, in a
program that reads attacker-controlled input. On x86_64 `div` and `idiv` take a
single explicit operand — the divisor — and the CPU raises a divide-error
exception (#DE, delivered as `SIGFPE`) when it is zero, crashing the process. On
AArch64 the divisor is the *third* operand of `sdiv`/`udiv`
(`sdiv Wd, Wn, Wm` → `Wm`); ARMv8 defines integer divide-by-zero as producing
`0` (it does **not** trap), so the AArch64 consequence is a silently-wrong `0`
result an attacker can force rather than a crash. Either way, if an attacker can
drive the divisor to zero — the classic `x / atoi(user_input)` with no
`if (d == 0)` check — that unguarded division is the weakness CWE-369 names.

The check walks each function for division instructions and **excludes** any
whose divisor is the subject of a preceding zero-check — on x86_64 a `cmp`/`test`
followed by a conditional jump, on AArch64 a `cbz`/`cbnz` on the divisor or a
`cmp`/`tst` followed by a `b.<cond>` branch — i.e. a guard like
`if (d == 0) return;`. (At `-O0` the AArch64 guard often tests a sibling register
reloaded from the divisor's stack slot; the check tracks the slot so that still
counts as a guard.) Excluding guarded divisions is what holds the
zero-false-positive line: a program that checks its divisor is not vulnerable and
is never flagged (the `safe_ratio` companion in the fixtures is silent). An
attacker-controlled input source (`fgets`/`scanf`/`read`/`atoi`/`strtol`…) must
also be present — a divisor the program never sourced from input cannot be driven
to zero by an attacker.

Findings carry `confidence: "medium"`: an unguarded divisor co-located with an
input source is a strong structural signal, but the check does not prove a
register-level def-use chain from the specific read to the divisor.

This is an **arch-aware register-level** detector: the engine knows both the
x86_64 (`div`/`idiv`) and AArch64 (`sdiv`/`udiv`) divisor/guard forms, so — like
CWE-732, CWE-190, CWE-134 and CWE-415 — it runs on **both x86_64 and AArch64**
(the `tests/fixtures/cwe369-aarch64-vuln` ARM64 fixture exercises it). It is
*not* skipped on AArch64.

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
  "evidence": "unguarded integer division (divisor dword ptr [rbp - 8]) in risky_ratio with no zero-check; attacker input via atoi() can drive the divisor to zero (SIGFPE on x86_64; a silently-wrong 0 result on AArch64)",
  "confidence": "medium"
}
```

### CWE-732 — incorrect permission assignment for a critical resource

A permission-setting call whose **mode is a compile-time literal that grants
write access beyond the owner** — the classic `chmod(path, 0777)` /
`chmod(path, 0666)` mistake — or a `umask()` whose mask fails to strip the
group/other write bits (e.g. `umask(0)`). Either makes a file (or every file the
process subsequently creates) writable by users other than its owner, so a local
attacker can tamper with a config file, a key, a log, or a setuid helper that
should have been owner-only. This is the weakness CWE-732 names.

The check reads the mode out of the call's argument register, walking back from
the call to resolve the immediate. The register mapping is per-architecture —
x86_64 SysV (`rsi` for `chmod`/`fchmod`/`lchmod`, `rdx` for `fchmodat`, `rdi`
for `umask`) and AArch64 AAPCS64 (`x1`/`w1` for `chmod`/`fchmod`/`lchmod`,
`x2`/`w2` for `fchmodat`, `x0`/`w0` for `umask`). It flags `chmod`-family calls
whose mode sets the group-write (`0o020`) or world-write (`0o002`) bit, and
`umask` calls whose mask does not strip **both** of those bits.

Zero-false-positive posture: a mode/mask **computed at runtime** (loaded from a
register or stack slot) has an unknown value and is never flagged — only
provably-permissive literals fire. A restrictive `chmod(path, 0600)` is silent,
and a `umask(0o077)`/`umask(0o022)` is silent too (the `lock_down` and
`tight_umask` companions in the fixture stay quiet). Like CWE-676/377/338,
CWE-732 needs no attacker-input source: an over-permissive permission literal is
the weakness itself.

`chmod`-family findings carry `confidence: "high"` (a definitive over-permissive
literal); `umask` findings carry `confidence: "medium"` (a process-wide policy
whose impact depends on what files are later created).

This is an **arch-aware register-level** detector: because it reads only a single
mode/mask immediate out of the (per-architecture) argument register, it runs on
**both x86_64 and AArch64** — unlike the other register-level checks, it is *not*
skipped on AArch64 (the `tests/fixtures/cwe732-aarch64-vuln` ARM64 fixture
exercises this).

```bash
autopsy --binary tests/fixtures/cwe732-vuln --checks 732 --format json
```

```json
{
  "cwe": 732,
  "function": "expose_secret",
  "address": "0x40114e",
  "taint_trace": [
    {"address": "0x40114e", "description": "chmod() called with over-permissive mode 0o777"}
  ],
  "evidence": "chmod() sets mode 0o777 in expose_secret: grants group-write and world-write access, making the resource writable beyond its owner; restrict to 0o600/0o644 (owner-write only)",
  "confidence": "high"
}
```

### CWE-476 — NULL pointer dereference

A pointer returned by a **NULL-returning allocator** that is **dereferenced
before it is checked against NULL**. The textbook case is
`p = malloc(n); p[0] = ...;` with no `if (p == NULL)`: when the allocation
fails `malloc()` returns NULL, the store faults on the unmapped zero page
(SIGSEGV), and on some targets an attacker who can force the failure escalates
the crash into a controlled write. CWE-476 is one of the most frequently
reported weakness classes in C/C++ and a perennial CWE Top 25 entry.

The check tracks the allocators whose contract is "returns NULL on
failure/absence" — `malloc`, `calloc`, `realloc`, `reallocarray`, `strdup`,
`strndup`, `getenv`, `secure_getenv`. The result arrives in `rax` (x86_64
SysV); -O0 codegen spills it to a stack slot, and a later use reloads the slot
and dereferences it. autopsy finds each allocator call, locates that slot, and
flags the first dereference through it — **unless a NULL-check guard
(`test`/`cmp` on the result, followed by a conditional branch) intervenes
first**.

Zero-false-positive posture: `p = malloc(n); if (!p) return; p[0] = ...;`
checks before it uses and is silent (the `safe_fill` and `safe_env` companions
in the fixture stay quiet). A result that is never spilled, never
dereferenced, or dereferenced only after a guard is not reported. Like
CWE-732/676/377, CWE-476 needs no attacker-input source: the missing NULL-check
is the weakness itself. Findings carry `confidence: "medium"` — an unchecked
dereference of an allocator result is a strong structural signal, but the
slot tracking is not a full def-use proof of the faulting pointer on every path.

This is a **register-level** detector (it reads the x86_64 result register and
stack slots), so it runs on **x86_64 only** and is skipped on AArch64.

```bash
autopsy --binary tests/fixtures/cwe476-vuln --checks 476 --format json
```

```json
{
  "cwe": 476,
  "function": "risky_fill",
  "address": "0x40119a",
  "taint_trace": [
    {"address": "0x40118d", "description": "malloc() may return NULL (allocation failure / absent value)"},
    {"address": "0x40119a", "description": "dereference of the malloc() result with no intervening NULL-check"}
  ],
  "evidence": "pointer returned by malloc() in risky_fill is dereferenced with no NULL-check; a failed/absent malloc() returns NULL and the dereference faults (SIGSEGV)",
  "confidence": "medium"
}
```

### CWE-362 — async-signal-unsafe call inside a signal handler (race condition)

A function installed as a signal handler — via `signal(sig, handler)` or one
of its BSD/SysV aliases (`__sysv_signal`/`bsd_signal`/`sysv_signal`/`sigset`)
— calls a libc function that is **not** on the POSIX.1-2017 §2.4.3
async-signal-safe list. A signal can land at any instruction boundary on the
same thread, including in the middle of a libc call already in progress. If
the handler then invokes the *same* family — `printf` while the main flow was
inside `printf` (FILE-lock recursion / stdio-buffer corruption), `malloc`
while the main flow was inside `malloc` (heap-arena reentrancy / deadlock) —
the shared global state races with itself. This is the canonical
"improper-synchronization-of-a-shared-resource" race weakness MITRE classes
under CWE-362, distinct from the CWE-367 TOCTOU file-system race.

The detector is **mostly call-site-driven**, plus one narrow form of pointer
resolution: it walks back from each `signal(sig, handler)` call to read the
*absolute address* loaded into the second argument register (SysV `rsi` on
x86_64, AAPCS64 `x1` on AArch64) and resolves that address to a function via
the CFG. The engine recognizes the x86_64 `lea rsi, [rip + disp]` /
`lea rax, [rip + disp] ; mov rsi, rax` RIP-relative form (the canonical -O0
emission for a function-address literal) and the AArch64 `adrp x1, page ;
add x1, x1, #:lo12:sym` page+offset form. Handlers passed by *indirection* —
loaded from a struct field, returned by an earlier call — are intentionally
unresolvable and stay silent, preserving the zero-false-positive posture. For
each resolved handler, every direct call to a function on the async-signal-
unsafe list is reported as a separate finding anchored at the unsafe call.

The async-signal-unsafe set targets the high-signal categories enumerated by
POSIX: buffered stdio (`printf`/`fprintf`/`puts`/`fputs`/`fopen`/`fclose`/
`fread`/`fwrite`/`fflush`/`fgets`), locale-sensitive formatters/scanners
(`sprintf`/`snprintf`/`sscanf`/`scanf`/`__isoc99_*`/`localtime`/`ctime`/
`asctime`/`gmtime` non-reentrant variants), the dynamic-allocator family
(`malloc`/`calloc`/`realloc`/`reallocarray`/`free`/`strdup`/`strndup`),
`syslog`, and `exit` (which runs `atexit` hooks and flushes stdio — the safe
forms are `_Exit`/`_exit`). The bounded scanf/printf siblings and the
descriptor-level I/O (`write`/`read`) are intentionally absent — they are on
the POSIX safe list and must never fire.

Like CWE-676/367/377, CWE-362 needs no attacker-input source: every signal
delivery is the asynchronous "input" that materializes the race. Findings
carry `confidence: "high"`: the handler-pointer→function resolution is exact
(an absolute literal address landing in a known function), and the
unsafe-call enumeration is exact (direct call to a named libc symbol on the
POSIX-unsafe list). The only soundness gap is unresolvable indirect-installed
handlers (e.g. via `sigaction(sig, &act, NULL)`, where `act.sa_handler` is a
struct field), which stay silent rather than false-positive.

The detector is **call-site-driven plus single-immediate-arg resolution** —
both halves are arch-aware on **x86_64 and AArch64**.

```bash
autopsy --binary tests/fixtures/cwe362-vuln --checks 362 --format json
```

```json
{
  "cwe": 362,
  "function": "unsafe_handler",
  "address": "0x4011a5",
  "taint_trace": [
    {"address": "0x401264", "description": "signal-installation: signal() registers unsafe_handler() as the handler — the handler can run asynchronously on the same thread"},
    {"address": "0x4011a5", "description": "async-signal-unsafe use: unsafe_handler() calls printf(), which shares global state (FILE locks / heap arena / locale buffers) with the interrupted flow"}
  ],
  "evidence": "signal() installs unsafe_handler() as a signal handler, and unsafe_handler() calls async-signal-unsafe printf(); a signal delivered while the program is mid-printf() will reenter printf() inside the handler, racing the shared global state (POSIX.1-2017 §2.4.3 lists printf() as not async-signal-safe) — use only async-signal-safe primitives in the handler (e.g. write() instead of printf(), _Exit() instead of exit()), or set a sig_atomic_t flag and handle the work outside the handler",
  "confidence": "high"
}
```

> `sigaction()` is deliberately NOT handled in this release — its handler
> lives inside a `struct sigaction` referenced by pointer, which would require
> struct-field reasoning beyond the single-immediate-arg resolution this
> check stays in scope for. An installed-handler set imported via `sigaction`
> would currently miss findings rather than emit false positives, which is
> the conservative-safe failure mode.

### CWE-367 — time-of-check time-of-use (TOCTOU) race condition

A function that **checks a path by name and then uses a path by name**, leaving
a race window between the two. The textbook case is `access()` before `open()`:
a setuid program asks `access(path, W_OK)` "may the *real* user write here?", the
check passes, and the program then `open()`s the path with its elevated
privileges. An attacker who swaps `path` for a symlink in the interval (winning
the race) redirects the privileged write to a file the real user could never
have opened — a classic local privilege escalation. The same window exists for
any by-name check→use pair: `stat`/`lstat` followed by
`open`/`fopen`/`creat`/`unlink`/`rename`/`chmod`/`symlink` and friends. This is
the weakness CWE-367 names.

The detector is **call-site-driven**: it walks each function in address order
and pairs a by-name *check* call (`access`/`faccessat`/`stat`/`lstat` and
variants) with the first by-name *use* call that follows it. It resolves direct
calls by symbol name and never inspects registers, so — like CWE-78/338/377/
676 — it runs on **both x86_64 and AArch64**. The finding is anchored at the
time-of-use and records both program points in its `taint_trace`.

Zero-false-positive posture: the safe descriptor-based pattern (`open` once, then
`fstat`/`fchmod` on the returned **file descriptor**) does not match — those
operate on an `fd`, not a path, so they are absent from the use set and never
fire. A function that only checks (no following by-name use) or only uses (no
preceding check) is silent too; both halves must be co-located. Like CWE-377/676,
CWE-367 needs no attacker-input source — the check→use sequence is the structural
race. Findings carry `confidence: "medium"`: the sequence is a definitive
structural window, but autopsy does not prove the two calls reference the *same*
path string (that would require full taint analysis).

```bash
autopsy --binary tests/fixtures/cwe367-vuln --checks 367 --format json
```

```json
{
  "cwe": 367,
  "function": "access_then_open",
  "address": "0x4011e8",
  "taint_trace": [
    {"address": "0x4011ce", "description": "time-of-check: access() inspects the path by name"},
    {"address": "0x4011e8", "description": "time-of-use: open() operates on the path by name (window between the two is the race)"}
  ],
  "evidence": "access() checks a path by name and open() then operates on a path by name in access_then_open: an attacker who alters the path between the check and the use (a TOCTOU race, e.g. a symlink swap) makes open() act on a different object than access() vetted; open() first, then check the returned fd, or use access(..., AT_EACCESS) on a descriptor",
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
  call-site-driven checks plus the arch-aware register-level checks CWE-732 and
  CWE-190 — see [Architecture support](#architecture-support)).
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
