# autopsy — Post-v0.1 Directions

Ranked improvement candidates for autopsy, produced during Rotation 1 of Phase 2
(research lap, 2026-05-26). Each item is scored on three axes:

- **Value**: how much does this improve autopsy's detection power or integration
  fitness for real-world use?
- **Feasibility**: how tractable is implementation with the current angr/Python stack,
  within a single focused Phase 2 implement lap?
- **Urgency**: is the gap actively hurting users or blocking suite integration today?

Rankings are Tier 1 (implement next) → Tier 3 (later/harder/lower value).

---

## Tier 1 — Implement next

### 1. Double-free detection (CWE-415)

**What it is:** Detect the pattern where `free()` is called twice on the same
pointer within a function (or across a short call chain). CWE-415 is a natural
companion to the existing CWE-416 check — the detection machinery is nearly
identical: track `malloc` → `free` sequences, then check whether the same
slot/register is freed again before a new allocation intervenes.

**Why it's first:**
- CWE-416 (use-after-free) is already detected by autopsy at the intra-procedural
  level. The slot-tracking and alias-register infrastructure in `checks/cwe416.py`
  is directly reusable: instead of looking for a dereference after free, look for
  a second `call free` where rdi aliases the same slot.
- CWE-415 sits at rank #14 on the 2025 CWE Top 25 (MITRE/CISA). It has 9 entries
  in the CISA KEV catalog, meaning actively exploited in the wild.
- The detection is fully intra-procedural, matching autopsy's current capability
  scope — no new symbolic execution technique is required.
- Adding CWE-415 increases the suite's memory-safety coverage from 4 to 5 CWE
  classes with very low implementation risk.
- A new fixture (`tests/fixtures/cwe415-vuln.c`) is a trivial C program; the slow
  integration test is identical in shape to the CWE-416 slow test.

**Implementation sketch:**
```python
# In _scan_function (cwe416.py), after recording free_addr:
# Instead of hunting for a dereference, keep scanning for another `call free`
# where rdi aliases ptr_slot. If found → double-free finding.
```

The new check lives in `autopsy/checks/cwe415.py`, is registered in `CHECKS`,
and the scope layer gains `"415"` as a valid token.

---

### 2. SARIF output format (`--format sarif`) ✅ IMPLEMENTED (Rotation 3) — GitHub Code Scanning-ready (Rotation 10)

**Status:** Shipped in Rotation 3, then hardened in Rotation 10 to be directly
uploadable to **GitHub Code Scanning** (the integration this item's rationale
explicitly promised). The Rotation 10 changes are all in `autopsy/sarif.py` and
are angr-free / fully unit-tested: (1) every `result` now carries a
`physicalLocation.artifactLocation.uri` pointing at the analyzed binary —
GitHub Code Scanning drops results that lack a file artifact, so the prior
address-only locations would not have ingested — while still preserving the
precise `address.absoluteAddress`; (2) each `result` links its rule by
`ruleIndex` into `tool.driver.rules` (SARIF best practice for reliable rule
resolution); (3) `tool.driver` records `version`/`semanticVersion` so the
analyzer build is tracked by consumers; (4) the missing CWE-787 entry was added
to `_CWE_META`, so OOB-write findings emit a properly named rule
(name/description/helpUri) instead of the generic `CWE-787` fallback. The README
gained a "SARIF output and GitHub Code Scanning" section with a `gh api
.../code-scanning/sarifs` upload recipe. Six new unit tests in
`tests/unit/test_sarif.py` lock the behavior.

**What it was:** Add a `--format sarif` output mode that emits
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
JSON — the Static Analysis Results Interchange Format — alongside the existing
`--format json`.

**Why it's second:**
- SARIF is now the de-facto interchange standard for security static analysis.
  GitHub Code Scanning, VS Code (via the SARIF Viewer extension), Azure DevOps,
  and Semgrep all consume SARIF natively. Every serious SAST tool that targets
  integration into DevSecOps pipelines emits SARIF.
- autopsy's current JSON output is autopsy-specific and requires custom parsers to
  integrate with downstream tooling. SARIF output costs zero new detection logic
  and unlocks immediate GitHub integration: users can upload autopsy SARIF to
  GitHub's `/code-scanning/sarifs` API and see findings annotated inline in PRs.
- The mapping is clean: one `run` entry, one `tool` descriptor per CWE check, one
  `result` per `Finding`, `locations[].physicalLocation.address.absoluteAddress`
  for the binary address, and `relatedLocations` for the taint trace.
- CWE ids map directly to SARIF's `taxa` array under the CWE taxonomy
  (`"guid": "1F9...", "name": "CWE-119"`).
- No new dependencies: SARIF is pure JSON. The implementation is a new
  `autopsy/sarif.py` emitter called from `cli.py` when `--format sarif` is passed,
  plus corresponding unit tests (no angr import needed).

**Implementation sketch:**
```python
def to_sarif(report: Report) -> dict:
    # Returns a SARIF 2.1.0-compliant dict
    # tool.driver.rules = [{id: "CWE-N", ...} for cwe in report.checks]
    # results = [{ruleId: "CWE-N", message: evidence, locations: [...], ...}]
    ...
```

---

## Tier 2 — High value, moderate scope

### 3. AArch64 (ARM64) architecture support — ✅ COMPLETE (all checks arch-aware as of Rotation 31)

**Status:** In progress. The v0.1 x86_64-only scope guard has been lifted —
`assert_supported()` accepts `AARCH64`, `_resolve_call_target` parses the
AArch64 `bl #0x…` operand form, and the call-graph traversal selects the `bl`
direct-call mnemonic per-architecture. The call-site-driven checks
(CWE-78/338/367/377/676) run unchanged on AArch64. **Two register-level checks
have now been made arch-aware: CWE-732 and CWE-190.** CWE-732 (incorrect
permission assignment) reads its mode/mask immediate out of the AAPCS64 argument
register (`x1`/`w1` for `chmod`, `x2`/`w2` for `fchmodat`, `x0`/`w0` for `umask`,
including the `mov w0, wzr` zero-register encoding of `umask(0)`). **CWE-190
(integer overflow into an allocator size) was previously listed as
"call-site-driven" but actually inspects the 32-bit size-arithmetic register
before the allocator call — and its detection logic recognized only x86 mnemonics
(`imul`/`shl`/`sal`/`lea`) and `e**`/`r**d` registers, so it silently found
nothing on AArch64 despite being in the arch-agnostic set.** The arithmetic
discovery has now been moved into the arch-aware engine helper
`size_arith_before_call`, which recognizes the AArch64 forms too
(`mul`/`madd`/`add`/`lsl` over `w0..w30` — `count * 4096` → `lsl w8, w8, #0xc`
(medium), `count * width` → `mul w8, w8, w9` (high)). **CWE-134 (uncontrolled
format string) is now arch-aware too:** the engine helper
`format_string_sinks_with_nonliteral_format` reads the printf-family
format-string argument out of the AAPCS64 register (`x0` for `printf`, `x1` for
`fprintf`/`sprintf`/`syslog`, `x2` for `snprintf`) and recognizes both the
x86_64 rodata-literal form (`lea reg, [rip+disp]`) and the AArch64 one
(`adrp`/`adr`), treating a stack-slot reload (`ldr xN, [sp, #N]`) as the
non-literal/attacker-controlled format. Freestanding AArch64 fixtures
(`tests/fixtures/cwe732-aarch64-vuln`, `tests/fixtures/cwe190-aarch64-vuln`,
`tests/fixtures/cwe134-aarch64-vuln`) plus unit and slow tests lock all three
behaviors. **CWE-369/415/416 are now arch-aware too** (divide-by-zero,
double-free, use-after-free — see the per-check shipped notes), as is
**CWE-119** (buffer over-read/write via an attacker-controlled index): the engine
helper `AngrEngine.indexed_memory_access_without_bounds_check` recognizes the
AArch64 codegen — the int index sign-extended with `ldrsw`/`sxtw`, the address
formed with an explicit base+index sum (`add xD, xBase, xIdx`), the dereference
through that base register (`str`/`ldr`/`strb`/`ldrb` over `[xD]`), and the
bounds-check guard (`cmp`/`subs`/`tst`/`tbz`/`tbnz`/`cbz`/`cbnz` + `b.<cond>`) —
alongside the x86_64 scaled-index-operand form, with a freestanding
`tests/fixtures/cwe119-aarch64-vuln` fixture and unit + slow tests.
**CWE-787 (heap OOB write via malloc + bulk-copy taint mismatch) is now
arch-aware too** (Rotation 30): the allocator/source/copy call-site discovery
was already arch-agnostic, and the literal-length suppression helper
`AngrEngine.copy_call_length_is_literal` now reads the AAPCS64 length-argument
register (`x2`/`w2`) for `memcpy`/`memmove`/`memset`/`strncpy`/`strncat`/
`bcopy`, recognizing both the immediate form (`mov w2, #imm` and the
`mov w2, wzr` zero-register encoding) and the stack-slot reload form
(`ldr w2, [sp, #N]`/`ldursw`). A freestanding `tests/fixtures/cwe787-aarch64-vuln`
fixture exercises both the vulnerable `copy_to_heap()` (memcpy with a
stack-reloaded length — fires) and the safe `safe_copy()` (strncpy with a
63-byte immediate length — must not fire). **CWE-476 (NULL-pointer
dereference) is now arch-aware too** (Rotation 31), closing the AArch64
porting work for this item: the engine helper
`AngrEngine.unchecked_alloc_dereferences` now dispatches by architecture and
carries a parallel AArch64 walker (`_unchecked_alloc_dereferences_aarch64` +
`_record_unchecked_deref_aarch64`) that tracks the allocator's return
register `x0` into a stack slot (`str x0, [sp, #N]` / `[x29, #N]`), follows
alias propagation through slot reloads (`ldr xR, [sp, #N]`) and
register-to-register copies (`mov xA, xB`), and recognizes the AArch64
NULL-check guard idioms — `cbz` / `cbnz` on a slot-aliased register, and
`cmp xR, #0` / `cmp xR, xzr` / `tst xR, xR` followed by `b.<cond>`. A
freestanding `tests/fixtures/cwe476-aarch64-vuln` fixture exercises both the
vulnerable `risky_fill()` (unchecked malloc deref — fires) and the safe
`safe_fill()` / `safe_env()` companions (each `cbnz`-guarded — must not
fire). With CWE-476 ported, **every** register-level check is arch-aware and
nothing is skipped on AArch64.

**What it is:** Lift the v0.1 x86_64-only scope guard to also accept
`aarch64`/`arm64` ELF binaries.

**Why it matters:**
- The 2025 binary analysis landscape is increasingly AArch64-first: Apple silicon,
  Android native code, AWS Graviton infrastructure, and IoT/embedded Linux all
  produce AArch64 ELFs.
- angr supports AArch64 via VEX IR (libVEX lifts AArch64 natively). The CFGFast
  call-site traversal, `call_sites_to()`, and the reachability pass all work
  architecture-agnostically — they operate on VEX IR and capstone disassembly.
- The main risk: the four v0.1 checks use capstone register-name literals
  (`rax`, `rbp`, `rdi`, `rsp`) that are x86_64-specific. CWE-416's slot-tracking
  regex hardcodes `rbp`/`rsp`. AArch64 uses `x0`–`x30`, `sp`, `fp` instead.
  Making slot-tracking arch-aware (a `platform.py` abstraction keyed on
  `engine.project.arch.name`) is the implementation challenge.
- CWE-78 is the simplest: it relies only on call-site discovery, which capstone
  renders correctly for AArch64. **(Correction:** CWE-190 was originally assumed
  to be in the same purely-call-site bucket, but it inspects the size-arithmetic
  register and so needed arch-aware mnemonic/register recognition for AArch64 —
  now shipped via `size_arith_before_call`. CWE-732 and CWE-190 are the two
  register-level checks made arch-aware so far.)
- Remaining Phase 2 scope: **none** — every register-level check
  (CWE-732, CWE-190, CWE-134, CWE-369, CWE-415, CWE-416, CWE-119, CWE-787,
  CWE-476) and every call-site-driven check now runs on AArch64. The
  AArch64-on-AArch64 native install path (rather than the freestanding
  cross-build used for fixtures) is a separate, optional follow-on.

**Feasibility caveat:** Building AArch64 fixtures requires an AArch64 cross-compiler
(`aarch64-linux-gnu-gcc`) or QEMU. Alfred's host is x86_64 — confirm toolchain
availability before committing to this lap.

---

### 4. Interprocedural use-after-free (CWE-416 cross-function) ✅ IMPLEMENTED (Rotation 6)

**Status:** Shipped — the bounded single-hop subset described in the feasibility
caveat below. The registered CWE-416 check now runs two passes: the original
intra-procedural pass and a new single-hop interprocedural pass
(`autopsy/checks/cwe416_interproc.py`). The interprocedural pass is call-graph
driven: the engine identifies in-binary functions that free their *incoming
pointer parameter* (`AngrEngine.in_binary_callees_freeing_arg`), finds each
such function's callers (`AngrEngine.callers_of`), and checks whether a caller
dereferences the pointer it passed *after* the freeing call returns, with no
intervening call (`AngrEngine.caller_uses_arg_after_call`). Findings are merged
with the intra-procedural results (de-duplicated by use address; the
higher-fidelity intra finding wins). Cross-function findings carry
`confidence: "medium"`. Scope is deliberately one hop only — deeper chains are
not followed, preserving the zero-false-positive guarantee (verified on the
clean baseline). A new fixture `tests/fixtures/cwe416-interproc-vuln.c` exercises
the pattern; x86_64 only (SysV `rdi` first-arg + -O0 stack-slot conventions).

**What it was:** Extend the CWE-416 check from purely intra-procedural (free and
use in the same function) to detect the most common cross-function UAF pattern:
a pointer freed in a callee and then used in the caller, or freed in the caller
and passed to a callee that uses it.

**Why it matters:**
- The 2025 CWE Top 25 ranks CWE-416 at #7, with 14 CISA KEV entries (actively
  exploited). Real-world UAF bugs are almost exclusively cross-function: the
  freeing code and the dangling dereference live in different functions. autopsy's
  intra-procedural restriction is the most significant false-negative gap in the
  current v0.1 detection model.
- angr's call graph is already built by CFGFast. Extending the check to follow
  pointer arguments across one call level (caller-callee reachability, function
  summary propagation) is the standard technique (see UAFDetector, GUEB).

**Feasibility caveat:** Interprocedural analysis with sound alias reasoning risks
false positives and implementation complexity that may exceed a single Phase 2 lap.
A practical subset: detect the single-hop pattern (malloc in function A, free in
function A, pointer returned/stored and dereferenced in function B that A calls
directly). Scope carefully to avoid overrun.

---

### Additional shipped detector — Memory leak (CWE-401) ✅ IMPLEMENTED (Rotation 32)

**Status:** Shipped. A new CWE-401 (Missing Release of Memory after Effective
Lifetime) check detects the canonical intra-procedural leak: a call to an
*owned* allocator (`malloc`/`calloc`/`realloc`/`reallocarray`/`strdup`/
`strndup`) whose result is spilled to a stack slot and where the function
returns without **any** of the four common ownership-transfer paths — no
`free()`/`realloc()`/`reallocarray()` release of the slot, no reload of the
slot into the return register (`rax` on x86_64, `x0` on AArch64) before a
`ret`, no reload of the slot into an integer argument register before a
non-release call, and no store of an aliasing register to memory other than
the original spill slot. The engine helper
`AngrEngine.unfreed_allocations()` does the disassembly-level work, with
parallel x86_64 (SysV) and AArch64 (AAPCS64) walkers selected from
`project.arch.name`. `getenv`/`secure_getenv` are deliberately excluded from
the owned-allocator set — their return values point at libc-owned
environment storage that the caller must not free — so an unfreed `getenv()`
is never a leak (CWE-476 still tracks it for unchecked dereferences). The
check (`autopsy/checks/cwe401.py`) carries `confidence: "medium"`: an owned
allocator with no observed release or escape is a strong structural leak
signal, but the intra-procedural slot tracking is not a full ownership proof
(an alias path the scanner does not recognize could legitimately transfer
ownership without being visible). A new fixture
`tests/fixtures/cwe401-vuln.c` exercises the vulnerable `leaky()` (no
release, no escape — fires) against four ownership-transfer companions
(`safe_free()` releases via `free`; `safe_return()` returns the pointer;
`safe_handoff()` passes it to another function; `safe_stash()` stores it to
a global) that must each stay silent. The check is registered in `CHECKS`,
`"401"` is a valid `--checks` token, and CWE-401 has a canonical entry in
`CWE_CATALOG` so `--list-checks` and the SARIF rule descriptor share the
same metadata. CWE-401 is a perennial top-class weakness — long-running
services accumulate leaks into OOMs and DoS surfaces.

**Pivot note (R32):** The suggested CWE-190 (integer overflow) and CWE-416
(use-after-free) detectors were already shipped and arch-aware by R31, so
this rotation picked the next-best unimplemented memory-safety gap. CWE-401
is the natural sibling to CWE-415/416/476 (it reuses the same allocator-
slot tracking machinery the others built up) and was not in the prior
Tier 1/2 list, making it a clean additive ship.

---

### Additional shipped detector — Out-of-bounds read (CWE-125) ✅ IMPLEMENTED (Rotation 31)

**Status:** Shipped. A new CWE-125 (Out-of-Bounds Read) check ships as the
read-side complement of CWE-787. The detection model mirrors CWE-787's
malloc + bulk-sink co-location heuristic, just against read-shaped sinks —
`memcmp`/`strncmp`/`strncasecmp`/`memchr` — instead of write-shaped ones. A
finding fires when a function contains both an allocator
(`malloc`/`calloc`/`realloc`/`reallocarray`) call and at least one of those
bulk-read sinks whose length argument is *not* a compile-time literal, and
the program contains at least one attacker-controlled input source (same
`_SOURCES` set as CWE-787/CWE-190). Literal-length reads (e.g.
`memcmp(buf, magic, 4)`) are suppressed by the existing
`engine.copy_call_length_is_literal` helper — the read sinks were added to
both the SysV (`_COPY_SINK_LEN_REG`: `rdx`) and AAPCS64
(`_COPY_SINK_LEN_REG_AARCH64`: `x2`) length-register maps, so the suppression
generalizes transparently and CWE-125 is **arch-agnostic** on both x86_64
and AArch64 (it lives in `_ARCH_AGNOSTIC_CHECKS`). Findings carry
`confidence: "medium"` — the alloc/read mismatch is a tight structural
signal but the analysis does not symbolically prove M > N on all paths
(same disclosure as CWE-787). A new fixture `tests/fixtures/cwe125-vuln.c`
exercises the vulnerable `compare_from_heap()` (malloc + memcmp with a
non-literal length — fires) alongside a safe `safe_compare()` companion
(memcmp with a 4-byte literal — must not fire), and a freestanding slow
test locks the contract. The check is registered in `CHECKS`, `"125"` is a
valid `--checks` token, and CWE-125 has a canonical entry in `CWE_CATALOG`
so `--list-checks` and the SARIF rule descriptor share the same metadata.
CWE-125 is rank #6 on the 2025 MITRE/CISA CWE Top 25 with 12 CISA KEV
entries (actively exploited) — the highest-leverage memory-safety gap
remaining after CWE-787.

---

### 5. Out-of-bounds write (CWE-787) distinct from CWE-119

**What it is:** Add an explicit CWE-787 check that targets heap-buffer writes
specifically — malloc-allocated buffers where the write index is tainted and can
exceed the allocation size — distinct from the CWE-119 stack-indexed-write detection.

**Why it matters:**
- CWE-787 (Out-of-bounds Write) is rank #5 on the 2025 CWE Top 25 with 12 CISA KEV
  entries. CWE-125 (Out-of-bounds Read) is rank #6. Together they represent the
  single largest exploitable memory-safety class in C/C++ binaries.
- autopsy's CWE-119 check detects a subclass of this (scaled-index writes) but does
  not specifically target heap allocation overflows. A dedicated CWE-787 check
  would combine the `malloc` call-site tracking from CWE-190 with the CWE-119
  index-computation heuristics to identify heap writes that may exceed the
  allocated region.
- The BASICS tool (arXiv Nov 2025) achieves 92% precision on this class using angr.

---

### 6. Confidence scoring on findings ✅ IMPLEMENTED (Rotation 3)

**Status:** Shipped. Each `Finding` now carries a three-level `confidence` field
(`"high"` / `"medium"` / `"low"`, default `"medium"`) computed from the
specificity of the evidence each check gathered. The field lives on the shared
`binary_finding_schema.BinaryFinding` (additive, validated, default-safe so
existing producers like blight are unaffected) and propagates through the JSON
report, the pipeline adapter, and SARIF output. SARIF maps confidence to
`result.level` (`high`→`error`, `medium`→`warning`, `low`→`note`) and also
records the raw level in `result.properties.confidence`. Per-check scheme:
CWE-78 high for `exec*` sinks / medium for `system`/`popen`; CWE-119 high for a
symbolic register-index access / medium for the static index-extension
heuristic; CWE-190 high when both arithmetic operands are registers / medium
when one is an immediate; CWE-415 always high (definitive double-free); CWE-416
high when slot aliasing is confirmed via a stack-slot reload / medium for the
register-copy heuristic.

**What it was:** Attach a `confidence` field to each `Finding`, computed
from the specificity of the evidence gathered by the check. (The original note
suggested a 0.0–1.0 scalar; the shipped design uses the three-level scheme
described below, which is what the "Why it matters" rationale already called
for and is simpler to triage against.)

**Why it matters:**
- autopsy's v0.1 checks use heuristic detection — they are designed for zero false
  positives on the fixture binaries, but on real-world targets the heuristics will
  occasionally fire on benign patterns. Users have no signal about which findings
  are high-confidence (tight taint trace, clear sink) versus low-confidence
  (single call-site match, indirect taint).
- A simple three-level scheme suffices: `high` (taint trace through multiple
  program points confirmed, no bounds check observed), `medium` (source+sink both
  present, weak flow evidence), `low` (sink present but source uncertain).
- The `Finding` dataclass and `BinaryFinding` schema can carry this field without
  breaking existing consumers (it's additive). The pipeline adapter propagates it.
- Competitors like cwe-checker and Veracode surface confidence/severity; the
  absence of confidence scoring makes autopsy harder to triage.

---

### Additional shipped detector — Uncontrolled format string (CWE-134) ✅ IMPLEMENTED

**Status:** Shipped. A new CWE-134 (Use of Externally-Controlled Format String)
check detects printf-family calls (`printf`/`fprintf`/`sprintf`/`snprintf`/
`syslog` and the `v*`/`err`/`warn` variants) whose *format-string* argument is
not a compile-time string literal — the engine helper
(`AngrEngine.format_string_sinks_with_nonliteral_format`) walks back from each
sink and confirms the format-argument register (SysV: `rdi` for `printf`, `rsi`
for `fprintf`/`sprintf`/`syslog`, `rdx` for `snprintf`) is reloaded from a stack
slot rather than set via a `lea reg, [rip+disp]` rodata pointer or an immediate
address. The classic `printf(user_input)` pattern compiles to exactly this
shape. The check (`autopsy/checks/cwe134.py`) requires both a non-literal format
sink and at least one attacker-controlled input source in the program (the same
`_SOURCES` set as CWE-78), and reports `confidence: "medium"` — the non-literal
format is a tight structural signal but the analysis does not prove a
register-level def-use chain from the specific read to the format slot. **Now
arch-aware: runs on both x86_64 and AArch64** — the engine helper reads the
format-string argument out of the per-architecture register (SysV
`rdi`/`rsi`/`rdx`; AAPCS64 `x0`/`x1`/`x2`) and recognizes both the x86_64
rodata-literal form (`lea [rip+disp]`) and the AArch64 one (`adrp`/`adr`). A
fixture `tests/fixtures/cwe134-vuln` (x86_64) exercises the vulnerable
`printf(user)` and a safe literal-format companion that must not fire;
`tests/fixtures/cwe134-aarch64-vuln` mirrors it on ARM64. CWE-134 is rank #25 region of the historical CWE Top 25 and a
staple of the printf-family weakness class; full VEX-IR source→format taint is
the post-v0.1 deepening (see Tier 3 item #9).

---

### Additional shipped detector — Incorrect permission assignment (CWE-732) ✅ IMPLEMENTED (Rotation 18)

**Status:** Shipped. A new CWE-732 (Incorrect Permission Assignment for Critical
Resource) check detects two over-permissive permission patterns, both
angr-free and register-level: (1) a `chmod`/`fchmod`/`lchmod`/`fchmodat` call
whose *mode* argument is a compile-time immediate that sets the group-write
(`0o020`) or world-write (`0o002`) bit — the classic `chmod(path, 0777)` /
`chmod(path, 0666)` mistake; and (2) a `umask` call whose immediate mask fails
to strip **both** of those bits (e.g. `umask(0)`), leaving every subsequently
created file group/world-writable. Two engine helpers do the disassembly-level
work — `AngrEngine.chmod_calls_with_permissive_mode` (mode register: SysV `rsi`
for chmod/fchmod/lchmod, `rdx` for fchmodat) and
`AngrEngine.umask_calls_with_permissive_mask` (mask in `rdi`) — each walking
back from the call site to resolve the immediate through the `-O0` instruction
window and following register-copy aliases. A mode/mask **computed at runtime**
(loaded from a register or stack slot) is intentionally not flagged: its value
is unknown, so flagging would break autopsy's zero-false-positive posture. Like
CWE-676/377/338, CWE-732 needs no attacker-input source — the over-permissive
literal is the weakness itself, which is how MITRE frames it. `chmod`-family
findings report `confidence: "high"` (a definitive over-permissive literal);
`umask` findings report `confidence: "medium"` (a process-wide policy whose
impact depends on what files are later created). x86_64 only (register-level;
excluded from the arch-agnostic set and skipped on AArch64). The check lives in
`autopsy/checks/cwe732.py`, is registered in `CHECKS`, and `"732"` is a valid
`--checks` token. A fixture `tests/fixtures/cwe732-vuln.c` exercises the
vulnerable `chmod(0777)`/`chmod(0666)`/`umask(0)` against restrictive companions
(`chmod(0600)` in `lock_down()`, `umask(0077)` in `tight_umask()`) that must not
fire. CWE-732 sits in the access-control weakness family on the CWE Top 25 and
is the next angr-free heuristic after CWE-369 (divide-by-zero, R17).

---

## Tier 3 — Later / harder / lower near-term value

### 7. PE (Windows) binary support

**What it is:** Extend `assert_supported()` to accept PE/x86_64 targets.

**Why it's Tier 3:**
- angr supports PE loading via CLE's PE backend, so the engine layer requires
  minimal change. The risk is in import-symbol resolution: PE binaries use the IAT
  (Import Address Table) rather than PLT stubs, and `_resolve_call_target()` in
  `engine.py` is written for ELF PLT resolution. IAT-aware resolution is a
  non-trivial engine change.
- The necromancer suite's core user is the Linux/ELF offensive-security analyst.
  PE support is a significant scope expansion with modest near-term demand.

---

### 8. PoC input generation (angr path constraints → test case)

**What it is:** For CWE-78 and CWE-119 findings, use angr's path constraint solver
to produce a concrete stdin value that reaches the vulnerable path.

**Why it's Tier 3:**
- This was explicitly excluded from v0.1 as "No symbolic execution to PoC input
  generation." It requires full concolic path tracing from entry to the specific
  sink address, which is dramatically slower than the current bounded reachability
  pass and likely to hit path-explosion on real targets.
- The research (dAngr, 2025 NDSS BAR; ADFEmu) shows active work in this direction
  but also confirms the computational cost. A good Phase 2 scope is hard to define
  without risking a budget-exhausted outcome.
- The right approach is to add this as an optional `--poc` flag that runs only when
  explicitly requested, constrained to a very low state budget, and clearly marked
  as best-effort.

---

### 9. VEX IR taint analysis (replace heuristic capstone scanning)

**What it is:** Replace the current check-level detection strategy (capstone
mnemonic/operand pattern matching) with a proper VEX IR def-use / taint analysis
using angr's `RDA` (Reaching Definitions Analysis) or a custom VEX-level taint
propagator.

**Why it's Tier 3:**
- This is the "deeper abstract interpretation" direction noted in the `AngrEngine`
  Worker decision comment. It would improve soundness materially — VEX IR taint
  analysis is insensitive to compiler-specific codegen variation that breaks
  capstone heuristics.
- However, implementing a correct VEX-level taint propagator is a large-scope
  project (comparable to HermeScan or VYPER) that goes beyond a single Phase 2
  lap. It would likely require a full architecture review and rewrite of all four
  check modules.
- Schedule this when autopsy has users reporting false negatives caused by
  optimized codegen (O2/O3) defeating the current capstone heuristics.

---

### 10. Firmware / bare-metal ELF support

**What it is:** Handle ELF binaries that have no standard C runtime, no libc, and
no OS syscall interface — microcontroller firmware compiled for ARM Cortex-M or
RISC-V, for example.

**Why it's Tier 3:**
- angr supports blob loading but firmware analysis requires custom `SimProcedure`
  stubs for MMIO, RTOS primitives, and HAL calls. This is a substantial
  infrastructure effort (see ADFEmu, 2025).
- autopsy's detection strategy today relies on the presence of standard C library
  imports (`malloc`, `free`, `system`, `fgets`, etc.) as source/sink anchors. In
  firmware these are absent or renamed. The entire detection model needs rethinking.
- Defer until the ELF/x86_64 + AArch64 story is solid.

---

## Implementation order recommendation

```
Rotation 2:  CWE-415 double-free (#1)        — low scope, high return
Rotation 3:  SARIF output (#2)               — zero new detection risk, high integration value
Rotation 4:  AArch64 support (#3)            — medium scope, check toolchain first
Rotation 5:  Interprocedural CWE-416 (#4)    — bounded to one-hop, clear success criterion
Rotation 6:  CWE-787 (#5) or confidence (#6) — choose based on user feedback
```

Items #7–#10 are explicitly deferred; revisit when the Tier 1 and Tier 2 list is
exhausted or when user demand shifts priorities.

---

## Research sources consulted

- MITRE CWE Top 25 Most Dangerous Software Weaknesses 2025 (cwe.mitre.org)
- CISA 2025 CWE Top 25 (cisa.gov, December 2025)
- BASICS: Binary Analysis and Stack Integrity Checker System (arXiv 2511.19670, Nov 2025)
- LATTE: LLM-Powered Static Binary Taint Analysis (ACM TOSEM, dl.acm.org/doi/10.1145/3711816)
- HermeScan: Detecting Vulnerabilities in Linux-based IoT Firmware (NDSS 2024)
- dAngr: Lifting Software Debugging to a Symbolic Level (NDSS BAR 2025)
- angr documentation: CFG, Decompiler, VEX IR, AArch64 support (docs.angr.io)
- SARIF support for code scanning (docs.github.com)
- UAFDetector: Scalable Static Detection of Use-After-Free Vulnerabilities in Binary Code
- GUEB: Statically detecting use after free on binary code (Springer 2014)
- Using Binary Analysis Frameworks: The Case for BAP and angr (Springer 2019)
