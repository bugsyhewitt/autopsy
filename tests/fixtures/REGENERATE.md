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
| `cwe78-aarch64-vuln.c` + `cwe78-aarch64-stubs.c` / `cwe78-aarch64-vuln` | source + binary: **AArch64** OS command injection (exercises ARM64 support) |
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

## AArch64 (ARM64) fixture

`cwe78-aarch64-vuln` exercises autopsy's AArch64 support — the call-site-driven
CWE-78 check firing on a `bl` (branch-with-link) call to `system()`. Because the
host is x86_64 (no AArch64 libc/sysroot), it is built **freestanding** and linked
statically with stub libc/runtime symbols (`cwe78-aarch64-stubs.c`).

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
