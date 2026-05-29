# Regenerating the test fixtures

The `autopsy` slow test layer runs against pre-built, deliberately-vulnerable
x86_64 ELF binaries. **The binaries are committed to this repo** so that tests
run without a compiler. This file documents how to regenerate them if needed.

## What ships in the repo

| File | Role |
|---|---|
| `cwe119-vuln.c` / `cwe119-vuln` | source + binary: buffer over-read/write via attacker-controlled offset |
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
| `cwe78-aarch64-vuln.c` + `cwe78-aarch64-stubs.c` / `cwe78-aarch64-vuln` | source + binary: **AArch64** OS command injection (exercises ARM64 call-site support) |
| `cwe732-aarch64-vuln.c` + `cwe732-aarch64-stubs.c` / `cwe732-aarch64-vuln` | source + binary: **AArch64** incorrect permission assignment (exercises the arch-aware register-level CWE-732 check on ARM64) |
| `cwe190-aarch64-vuln.c` + `cwe190-aarch64-stubs.c` / `cwe190-aarch64-vuln` | source + binary: **AArch64** integer overflow into allocator size (exercises the arch-aware register-level CWE-190 check on ARM64) |
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
