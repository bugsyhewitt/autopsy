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
| `cwe78-vuln.c` / `cwe78-vuln` | source + binary: OS command injection into `system()` |
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
- If you change a `.c` file, keep the vulnerability pattern intact: the CWE-416
  fixture in particular **must remain intra-procedural** (malloc, free, and use
  in the same function with no calls between free and use).
