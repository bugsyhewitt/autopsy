# Regenerating the test fixtures

The `autopsy` slow test layer runs against pre-built, deliberately-vulnerable
x86_64 ELF binaries. **The binaries are committed to this repo** so that tests
run without a compiler. This file documents how to regenerate them if needed.

## What ships in the repo

| File | Role |
|---|---|
| `cwe119-vuln.c` / `cwe119-vuln` | source + binary: buffer over-read/write via attacker-controlled offset |
| `cwe125-vuln.c` / `cwe125-vuln` | source + binary: out-of-bounds heap *read* via malloc + bulk-read taint mismatch (`compare_from_heap()` malloc(size) + memcmp(buf, needle, length) fires; `safe_compare()` uses a literal 4-byte length and must not be flagged) |
| `cwe190-vuln.c` / `cwe190-vuln` | source + binary: integer overflow into allocator size |
| `cwe416-vuln.c` / `cwe416-vuln` | source + binary: intra-procedural use-after-free |
| `cwe416-interproc-vuln.c` / `cwe416-interproc-vuln` | source + binary: single-hop **interprocedural** use-after-free (free in callee, use in caller) |
| `cwe78-vuln.c` / `cwe78-vuln` | source + binary: OS command injection into `system()` |
| `cwe134-vuln.c` / `cwe134-vuln` | source + binary: uncontrolled format string (`printf(user_input)`); the safe `log_line()` uses a literal format and must not be flagged |
| `cwe676-vuln.c` / `cwe676-vuln` | source + binary: use of potentially dangerous functions (`gets`/`strcpy`/`sprintf`); the bounded siblings (`strncpy`/`snprintf`/`fgets`) must not be flagged |
| `cwe377-vuln.c` / `cwe377-vuln` | source + binary: insecure temporary files (`tmpnam`/`mktemp`/`tempnam`); the atomic `mkstemp()` in `safe_create()` must not be flagged |
| `cwe732-vuln.c` / `cwe732-vuln` | source + binary: incorrect permission assignment (`chmod(path,0777)`/`chmod(path,0666)`/`umask(0)`); the restrictive `chmod(path,0600)` in `lock_down()` and `umask(0077)` in `tight_umask()` must not be flagged |
| `cwe367-vuln.c` / `cwe367-vuln` | source + binary: TOCTOU race (`access`→`open`, `stat`→`fopen`, `lstat`→`unlink`); the descriptor-based `safe_open_then_fstat()` and the single-sided `only_check()`/`only_use()` must not be flagged |
| `cwe476-vuln.c` / `cwe476-vuln` | source + binary: NULL pointer dereference (`malloc()` result dereferenced with no NULL-check in `risky_fill()`); the NULL-checked `safe_fill()` and `safe_env()` must not be flagged |
| `cwe401-vuln.c` / `cwe401-vuln` | source + binary: memory leak (`malloc()` in `leaky()` is never freed, never returned, never passed out, never stored — the allocation leaks); the four ownership-transfer companions (`safe_free()` releases, `safe_return()` returns the pointer, `safe_handoff()` passes it to another function, `safe_stash()` stores it into a global) must each stay silent |
| `cwe78-aarch64-vuln.c` + `cwe78-aarch64-stubs.c` / `cwe78-aarch64-vuln` | source + binary: **AArch64** OS command injection (exercises ARM64 call-site support) |
| `cwe732-aarch64-vuln.c` + `cwe732-aarch64-stubs.c` / `cwe732-aarch64-vuln` | source + binary: **AArch64** incorrect permission assignment (exercises the arch-aware register-level CWE-732 check on ARM64) |
| `cwe190-aarch64-vuln.c` + `cwe190-aarch64-stubs.c` / `cwe190-aarch64-vuln` | source + binary: **AArch64** integer overflow into allocator size (exercises the arch-aware register-level CWE-190 check on ARM64) |
| `cwe134-aarch64-vuln.c` + `cwe134-aarch64-stubs.c` / `cwe134-aarch64-vuln` | source + binary: **AArch64** uncontrolled format string (exercises the arch-aware register-level CWE-134 check on ARM64) |
| `cwe415-aarch64-vuln.c` + `cwe415-aarch64-stubs.c` / `cwe415-aarch64-vuln` | source + binary: **AArch64** intra-procedural double-free (exercises the arch-aware register-level CWE-415 check on ARM64); the single free in `safe_free()` must not be flagged |
| `cwe416-aarch64-vuln.c` + `cwe416-aarch64-stubs.c` / `cwe416-aarch64-vuln` | source + binary: **AArch64** intra-procedural use-after-free (exercises the arch-aware register-level CWE-416 check on ARM64: free then dereference of the same pointer in `use_after_free()`); the freed-but-not-reused pointer in `safe_free()` must not be flagged |
| `cwe369-aarch64-vuln.c` + `cwe369-aarch64-stubs.c` / `cwe369-aarch64-vuln` | source + binary: **AArch64** divide-by-zero (exercises the arch-aware CWE-369 check on ARM64: unguarded `sdiv`/`udiv` in `risky_ratio()`); the zero-checked `safe_ratio()` must not be flagged |
| `cwe119-aarch64-vuln.c` + `cwe119-aarch64-stubs.c` / `cwe119-aarch64-vuln` | source + binary: **AArch64** buffer over-read/write via attacker-controlled index (exercises the arch-aware register-level CWE-119 check on ARM64: unguarded register-indexed store in `store_at()`); the range-checked `safe_store()` must not be flagged |
| `cwe787-aarch64-vuln.c` + `cwe787-aarch64-stubs.c` / `cwe787-aarch64-vuln` | source + binary: **AArch64** heap out-of-bounds write via malloc + bulk-copy taint mismatch (exercises the arch-aware CWE-787 check on ARM64: the tainted-length memcpy in `copy_to_heap()` fires); the literal-length `strncpy(p, line, 63)` in `safe_copy()` must not be flagged (the literal-length suppression catches it via the AAPCS64 `mov w2, #0x3f` form) |
| `clean-baseline.c` / `clean-baseline` | source + binary: none of the four classes (zero-false-positive check) |
| `Makefile` | build rules |

## Toolchain

- **Compiler:** `gcc` (clang also works; set `CC=clang`)
- **Target:** x86_64 Linux ELF (v0.1 supports x86_64 only)
- **Flags:** `-O0 -fno-stack-protector -no-pie -g` (see the Makefile for the
  rationale — `-O0` keeps taint flows visible, `-no-pie` keeps addresses
  stable, `-g` keeps function names resolvable)

Verified with:

```
gcc (GCC) 14.x / clang 18.x
```

## Regenerate

From this directory:

```bash
make clean
make all
```

This rebuilds all five binaries in place. Then re-run the slow suite to
confirm detection still holds:

```bash
pytest -m slow
```

## Notes

- Addresses in findings are not asserted as literal constants in the tests
  (only that they are present and well-formed), so a rebuild on a different
  toolchain that shifts addresses will not break the suite.
- If you change a `.c` file, keep the vulnerability pattern intact: the
  `cwe416-vuln` fixture **must remain intra-procedural** (malloc, free, and use
  in the same function with no calls between free and use), while the
  `cwe416-interproc-vuln` fixture **must remain single-hop interprocedural**
  (the pointer is freed inside a callee that receives it as an argument, then
  dereferenced in the caller after that call returns, with no intervening call).
- The `cwe676-vuln` fixture declares `gets` explicitly (`extern char *gets(...)`)
  because modern glibc/C11 headers no longer expose it; the symbol still links
  from libc so the `gets` call site resolves for the detector. The linker prints
  a "the `gets' function is dangerous" warning during the build — that is
  expected and is exactly the weakness the CWE-676 check flags.
- The `cwe377-vuln` fixture declares `tmpnam`/`tempnam`/`mktemp` explicitly
  (`extern char *tmpnam(...)`, etc.) because they are obsolescent and may be
  hidden behind feature guards; the symbols still link from libc so the call
  sites resolve for the detector. The linker prints "the use of `tmpnam'/`mktemp'
  /`tempnam' is dangerous" warnings during the build — those are expected and are
  exactly the weakness the CWE-377 check flags. The `mkstemp()` call in
  `safe_create()` is the atomic create-and-open replacement and must remain
  unflagged (zero false positives).
- The `cwe732-vuln` fixture sets over-permissive permission literals
  (`chmod(path, 0777)`, `chmod(path, 0666)`, `umask(0)`) that the CWE-732 check
  flags, alongside restrictive companions (`chmod(path, 0600)` in `lock_down()`
  and `umask(0077)` in `tight_umask()`) that must remain **unflagged**. Keep the
  mode/mask values as compile-time octal literals — the detector reads the
  immediate out of the mode-argument register (`esi`/`edx`/`edi`); a mode
  computed at runtime is intentionally not flagged.
- The `cwe476-vuln` fixture dereferences a `malloc()` result with no NULL-check
  in `risky_fill()` (the CWE-476 hit), alongside `safe_fill()` (which guards the
  result with `if (p == NULL) return`) and `safe_env()` (which NULL-checks the
  `getenv()` result) — both must remain **unflagged**. Keep `-O0` so the
  allocator result is spilled to a stack slot and the NULL-check stays a visible
  `cmp`/`test` + conditional branch; the detector recognizes that guard and is
  silent on the safe companions.

## AArch64 (ARM64) fixtures

`cwe78-aarch64-vuln` exercises autopsy's AArch64 support — the call-site-driven
CWE-78 check firing on a `bl` (branch-with-link) call to `system()`. Because the
host is x86_64 (no AArch64 libc/sysroot), it is built **freestanding** and linked
statically with stub libc/runtime symbols (`cwe78-aarch64-stubs.c`).

`cwe732-aarch64-vuln` exercises the **arch-aware register-level** CWE-732
permission check on AArch64: the chmod/umask mode immediate is read out of the
AAPCS64 argument register (`w1` for chmod, `w0` for umask, including the
`mov w0, wzr` zero-register encoding of `umask(0)`) materialized just before each
`bl` call. It uses the same freestanding cross-build recipe (stub libc in
`cwe732-aarch64-stubs.c`). Keep the mode/mask values as compile-time octal
literals — a value computed at runtime (loaded from memory) is intentionally not
flagged, preserving the zero-false-positive posture. Verify the codegen with:

```bash
llvm-objdump -d cwe732-aarch64-vuln | grep -B1 -A1 -iE 'mov\s+w[012]'
```

You should see `mov w1, #0x1ff` (0o777) and `mov w1, #0x1b6` (0o666) before
their `bl <chmod>` calls and `mov w0, wzr` (umask(0)) before its `bl <umask>`,
with the restrictive `mov w1, #0x180` (0o600) and `mov w0, #0x3f` (0o077) that
must stay unflagged.

`cwe190-aarch64-vuln` exercises the **arch-aware register-level** CWE-190
integer-overflow check on AArch64: the 32-bit size arithmetic before the
`bl <malloc>` call is the overflow surface. `count * 4096` lowers to
`lsl w8, w8, #0xc` (a register source plus an immediate shift -> medium
confidence, mirroring the x86_64 `shl eax, 0xc`); a `count * width` multiply
would lower to `mul w8, w8, w9` (two register sources -> high). The check pairs
that arithmetic with the attacker-input source (`fgets`/`atoi`). Same
freestanding cross-build recipe (stub libc in `cwe190-aarch64-stubs.c`). Verify
the codegen with:

```bash
llvm-objdump -d cwe190-aarch64-vuln | grep -A10 '<alloc_records>:'
```

You should see `lsl w8, w8, #0xc` followed (a few instructions later) by
`bl ... <malloc>`, with `bl ... <fgets>` and `bl ... <atoi>` in `main`.

`cwe134-aarch64-vuln` exercises the **arch-aware register-level** CWE-134
uncontrolled-format-string check on AArch64: the printf-family *format-string*
argument is read out of the AAPCS64 argument register (`x0` for printf, `x1` for
fprintf) just before the `bl` call. A stack-slot reload (`ldr x0, [sp, #N]`) is
the non-literal/attacker-controlled format the check flags; the safe `log_line()`
materializes a rodata literal via `adrp`/`adr` and must NOT fire. The check pairs
the non-literal format with the attacker-input source (`fgets` in `main`). Same
freestanding cross-build recipe (stub libc in `cwe134-aarch64-stubs.c`). Verify
the codegen with:

```bash
llvm-objdump -d cwe134-aarch64-vuln | grep -A12 '<emit>:'
llvm-objdump -d cwe134-aarch64-vuln | grep -A14 '<log_line>:'
```

You should see `ldr x0, [sp, #0x8]` then `bl ... <printf>` in `<emit>` (the
vulnerable non-literal format), and `adr x0, ...` (or `adrp x0`) then
`bl ... <printf>` in `<log_line>` (the safe rodata literal that must stay
unflagged).

`cwe415-aarch64-vuln` exercises the **arch-aware register-level** CWE-415
intra-procedural double-free check on AArch64: the allocator return register
(`x0`) is spilled to a stack slot (`str x0, [sp, #N]`) and reloaded
(`ldr x0, [sp, #N]`) before each `bl <free>` call. Two successive `bl <free>`
calls whose `x0` aliases the same slot, with NO function call between them, are
the double-free the check flags (high confidence, mirroring the x86_64
`mov [rbp-N], rax` / `mov rdi, [rbp-N]` / `call free` form). The safe companion
`safe_free()` frees the pointer once and must NOT fire. Same freestanding
cross-build recipe (stub libc in `cwe415-aarch64-stubs.c`). Keep the two frees
in `double_free()` adjacent with no intervening call so the pattern stays
intra-procedural. Verify the codegen with:

```bash
llvm-objdump -d cwe415-aarch64-vuln | grep -A14 '<double_free>:'
llvm-objdump -d cwe415-aarch64-vuln | grep -A12 '<safe_free>:'
```

You should see `str x0, [sp, #0x8]` then two `ldr x0, [sp, #0x8]` / `bl <free>`
pairs in `<double_free>` (the double-free), and a single `ldr x0, [sp, #0x8]` /
`bl <free>` in `<safe_free>` (the safe single free that must stay unflagged).

`cwe416-aarch64-vuln` exercises the **arch-aware register-level** CWE-416
intra-procedural use-after-free check on AArch64: like CWE-415, the allocator
return register (`x0`) is spilled to a stack slot (`str x0, [sp, #N]`) and
reloaded (`ldr x0, [sp, #N]`) before the `bl <free>` call. The use-after-free
signal is, after the free and with NO function call between, a reload of the same
slot into a register and a **dereference** through that base register
(`strb wN, [x9]`) — mirroring the x86_64 `mov rax, [rbp-N]` / `mov [rax], ...`
form, flagged at high confidence because the dereferenced register is a confirmed
slot reload. The safe companion `safe_free()` frees a pointer it never reuses and
must NOT fire. Same freestanding cross-build recipe (stub libc in
`cwe416-aarch64-stubs.c`). Keep the dereference in `use_after_free()` adjacent to
the free with no intervening call so the pattern stays intra-procedural. Verify
the codegen with:

```bash
llvm-objdump -d cwe416-aarch64-vuln | grep -A12 '<use_after_free>:'
llvm-objdump -d cwe416-aarch64-vuln | grep -A10 '<safe_free>:'
```

You should see `str x0, [sp, #0x8]`, then `ldr x0, [sp, #0x8]` / `bl <free>`,
then `ldr x9, [sp, #0x8]` / `strb w8, [x9]` in `<use_after_free>` (the
reload-and-dereference of the freed pointer). `<safe_free>` ends at its single
`ldr x0, [sp, #0x8]` / `bl <free>` with no later dereference (must stay
unflagged).

`cwe369-aarch64-vuln` exercises the **arch-aware** CWE-369 divide-by-zero check
on AArch64: the divisor is the *third* operand of `sdiv`/`udiv`
(`sdiv Wd, Wn, Wm` -> `Wm`). An unguarded division — no `cbz`/`cbnz` on the
divisor and no `cmp`/`tst` + `b.<cond>` before it — co-located with an
attacker-input source (`fgets`/`atoi`) is the CWE-369 site (`risky_ratio()`,
medium confidence). The safe companion `safe_ratio()` zero-checks the divisor
(at `-O0` clang emits `cbnz` on a sibling register reloaded from the divisor's
stack slot) and must NOT fire. ARMv8 defines integer divide-by-zero as producing
`0` (it does **not** trap like x86_64's `#DE`/SIGFPE), so on AArch64 the
weakness is a silently-wrong result an attacker can force rather than a crash —
but the missing zero-check is still the bug, and autopsy flags it identically.
Same freestanding cross-build recipe (stub libc in `cwe369-aarch64-stubs.c`).
Verify the codegen with:

```bash
llvm-objdump -d cwe369-aarch64-vuln | grep -A8 '<risky_ratio>:'
llvm-objdump -d cwe369-aarch64-vuln | grep -A18 '<safe_ratio>:'
```

You should see `sdiv w0, w8, w9` with no preceding `cbz`/`cbnz`/`cmp` on `w9` in
`<risky_ratio>` (the unguarded divide), and a `cbnz w8, ...` guard before the
`sdiv w8, w8, w9` in `<safe_ratio>` (the zero-check that must stay unflagged),
with `bl ... <fgets>` and `bl ... <atoi>` in `<main>`.

`cwe119-aarch64-vuln` exercises the **arch-aware register-level** CWE-119
buffer over-read/write check on AArch64. At `-O0` a `buf[idx]` access lowers to:
the int index is sign-extended (`ldrsw x10, [sp, #N]`), the buffer address is
formed with an explicit base+index sum (`adr x9, <buf>` / `add x9, x9, x10`), and
the store dereferences that base register (`strb w8, [x9]`). The register index
makes the offset genuinely data-dependent ("symbolic") -> high confidence,
mirroring the x86_64 symbolic scaled-index operand `[rax+rdx]`. The vulnerable
`store_at()` does this with NO bounds check; the safe `safe_store()`
range-checks the index first (`tbnz w8, #0x1f, ...` for `idx < 0` and
`subs w8, w8, #0x10` / `b.lt ...` for `idx >= 16`) and must NOT fire. The check
pairs the unguarded indexed access with the attacker-input source (`fgets`/`atoi`
in `main`). Same freestanding cross-build recipe (stub libc in
`cwe119-aarch64-stubs.c`). Keep the index coming from a function parameter so the
compiler does not fold it to a constant, and keep `safe_store()`'s range check
intact. Verify the codegen with:

```bash
llvm-objdump -d cwe119-aarch64-vuln | grep -A12 '<store_at>:'
llvm-objdump -d cwe119-aarch64-vuln | grep -A22 '<safe_store>:'
```

You should see `ldrsw x10, [sp, #0xc]` / `add x9, x9, x10` / `strb w8, [x9]` with
no preceding `cmp`/`subs`/`tbnz` in `<store_at>` (the unguarded indexed write),
and a `tbnz`/`subs`+`b.lt` guard before the same `add`/`strb` sequence in
`<safe_store>` (the bounds check that must stay unflagged), with
`bl ... <fgets>` and `bl ... <atoi>` in `<main>`.

`cwe787-aarch64-vuln` exercises the **arch-aware** CWE-787 heap out-of-bounds
write check on AArch64. The detection model is the same as on x86_64 — a
malloc + bulk-copy/fill co-located in one function, with a copy whose length
argument is NOT a compile-time literal — but the literal-length suppression
helper now reads the AAPCS64 length-argument register `x2`/`w2`. At `-O0`,
`copy_to_heap()` materializes the tainted length with a stack-slot reload
(`ldrsw x2, [sp, #0x8]`) before `bl <memcpy>` (must fire — non-literal),
while `safe_copy()` materializes the constant 63 as `mov x2, #0x3f` (or
`mov w2, #0x3f`) before `bl <strncpy>` (must NOT fire — literal length, the
suppression catches it). The check pairs both functions with the
attacker-input source (`fgets`/`atoi` in `main`). Same freestanding
cross-build recipe (stub libc in `cwe787-aarch64-stubs.c`). Keep the
allocation/copy length in `copy_to_heap()` coming from function parameters
(so the length is reloaded from a stack slot and not folded to a constant),
and keep the `63` in `safe_copy()` as a compile-time literal. Verify the
codegen with:

```bash
llvm-objdump -d cwe787-aarch64-vuln | grep -A12 '<copy_to_heap>:'
llvm-objdump -d cwe787-aarch64-vuln | grep -A14 '<safe_copy>:'
```

You should see `ldrsw x2, [sp, #N]` (or `ldr w2, [sp, #N]`) immediately before
`bl ... <memcpy>` in `<copy_to_heap>` (the tainted runtime length), and
`mov x2, #0x3f` (or `mov w2, #0x3f`) immediately before `bl ... <strncpy>` in
`<safe_copy>` (the literal length that must stay unflagged), with
`bl ... <fgets>` and `bl ... <atoi>` in `<main>`.

Toolchain:

- **Compiler:** `clang` with `--target=aarch64-linux-gnu` (the bundled LLVM
  AArch64 backend; no cross-gcc or sysroot required)
- **Linker:** `ld.lld`
- **Flags:** `-ffreestanding -fno-stack-protector -O0 -g`

Regenerate just this fixture from this directory:

```bash
make aarch64
```

The detection signal is purely the presence and resolvable symbol names of the
`bl` call sites in `run_cmd()`; the stub bodies are irrelevant. Verify with:

```bash
llvm-objdump -d cwe78-aarch64-vuln | grep -A14 '<run_cmd>:'
```

You should see `bl ... <fgets>` followed by `bl ... <system>`.
