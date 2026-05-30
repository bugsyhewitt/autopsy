# Makefile for autopsy test fixtures.
#
# Produces deliberately-vulnerable x86_64 ELF binaries (plus one clean
# baseline) used by the slow test layer. Pre-built blobs are committed to the
# repo so that tests run without a compiler; this Makefile exists only for
# regeneration. See REGENERATE.md.
#
# Flags rationale:
#   -O0                  keep the source structure intact so taint flows are
#                        recognizable (no inlining/constant folding away sinks)
#   -fno-stack-protector remove stack canaries that obscure buffer logic
#   -no-pie              load at a fixed base so committed addresses are stable
#   -g                   include symbols so function names resolve in findings

CC      ?= gcc
CFLAGS  ?= -O0 -fno-stack-protector -no-pie -g
ARCH    ?= -m64

SRCS := cwe119-vuln.c cwe125-vuln.c cwe190-vuln.c cwe338-vuln.c cwe362-vuln.c cwe367-vuln.c cwe369-vuln.c cwe377-vuln.c cwe401-vuln.c cwe415-vuln.c cwe415-interproc-vuln.c cwe416-vuln.c cwe416-interproc-vuln.c cwe476-vuln.c cwe78-vuln.c cwe134-vuln.c cwe676-vuln.c cwe732-vuln.c cwe787-vuln.c clean-baseline.c
BINS := $(SRCS:.c=)

# AArch64 (ARM64) CWE-78 fixture. The host is x86_64, so the binary is built
# freestanding (no libc headers) with clang's cross target and linked statically
# with stub libc/runtime symbols. This produces a loadable AArch64 ELF whose
# `bl` call targets resolve to the symbol names fgets/system — the signal the
# call-site-driven CWE-78 check needs. See REGENERATE.md.
AARCH64_CC      ?= clang
AARCH64_TARGET  ?= --target=aarch64-linux-gnu
AARCH64_CFLAGS  ?= -ffreestanding -fno-stack-protector -O0 -g
AARCH64_LD      ?= ld.lld

.PHONY: all aarch64 clean

all: $(BINS) aarch64

%: %.c
	$(CC) $(ARCH) $(CFLAGS) -o $@ $<

aarch64: cwe78-aarch64-vuln cwe732-aarch64-vuln cwe190-aarch64-vuln cwe134-aarch64-vuln cwe415-aarch64-vuln cwe416-aarch64-vuln cwe369-aarch64-vuln cwe119-aarch64-vuln cwe787-aarch64-vuln cwe476-aarch64-vuln

cwe78-aarch64-vuln: cwe78-aarch64-vuln.c cwe78-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe78-aarch64-vuln.c -o cwe78-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe78-aarch64-stubs.c -o cwe78-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o

# AArch64 CWE-732 fixture: exercises the arch-aware register-level permission
# check. The chmod/umask mode immediate is read from the AAPCS64 argument
# register (x1/w1 / x0/w0). Same freestanding cross-build recipe as CWE-78.
cwe732-aarch64-vuln: cwe732-aarch64-vuln.c cwe732-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe732-aarch64-vuln.c -o cwe732-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe732-aarch64-stubs.c -o cwe732-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe732-aarch64-vuln.o cwe732-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe732-aarch64-vuln.o cwe732-aarch64-stubs.o

# AArch64 CWE-190 fixture: exercises the arch-aware register-level integer-
# overflow check. The 32-bit size arithmetic (`lsl w8, w8, #0xc` for
# `count * 4096`) is found before the `bl malloc` call. Same freestanding
# cross-build recipe as CWE-78/CWE-732.
cwe190-aarch64-vuln: cwe190-aarch64-vuln.c cwe190-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe190-aarch64-vuln.c -o cwe190-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe190-aarch64-stubs.c -o cwe190-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe190-aarch64-vuln.o cwe190-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe190-aarch64-vuln.o cwe190-aarch64-stubs.o

# AArch64 CWE-134 fixture: exercises the arch-aware register-level
# uncontrolled-format-string check. The printf-family format argument is read
# out of the AAPCS64 argument register (`x0` for printf, `x1` for fprintf); a
# stack-slot reload (`ldr x0, [sp, #N]`) is the non-literal/attacker-controlled
# format, while the safe `log_line()` materializes a rodata literal via
# `adrp`/`adr`. Same freestanding cross-build recipe as CWE-78/CWE-732/CWE-190.
cwe134-aarch64-vuln: cwe134-aarch64-vuln.c cwe134-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe134-aarch64-vuln.c -o cwe134-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe134-aarch64-stubs.c -o cwe134-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe134-aarch64-vuln.o cwe134-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe134-aarch64-vuln.o cwe134-aarch64-stubs.o

# AArch64 CWE-415 fixture: exercises the arch-aware intra-procedural
# double-free check. The allocator result (`x0`) is spilled to a stack slot
# (`str x0, [sp, #N]`) and reloaded (`ldr x0, [sp, #N]`) before two successive
# `bl <free>` calls with no intervening call. The safe companion frees once.
# Same freestanding cross-build recipe as CWE-78/CWE-732/CWE-190/CWE-134.
cwe415-aarch64-vuln: cwe415-aarch64-vuln.c cwe415-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe415-aarch64-vuln.c -o cwe415-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe415-aarch64-stubs.c -o cwe415-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe415-aarch64-vuln.o cwe415-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe415-aarch64-vuln.o cwe415-aarch64-stubs.o

# AArch64 CWE-416 fixture: exercises the arch-aware intra-procedural
# use-after-free check. The allocator result (`x0`) is spilled to a stack slot
# (`str x0, [sp, #N]`) and reloaded (`ldr x0, [sp, #N]`) before a `bl <free>`
# call, then reloaded again after the free and dereferenced through that base
# register (`str`/`ldr ..., [x9]`) with no intervening call. The safe companion
# frees a pointer it never reuses. Same freestanding cross-build recipe as the
# other AArch64 fixtures.
cwe416-aarch64-vuln: cwe416-aarch64-vuln.c cwe416-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe416-aarch64-vuln.c -o cwe416-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe416-aarch64-stubs.c -o cwe416-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe416-aarch64-vuln.o cwe416-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe416-aarch64-vuln.o cwe416-aarch64-stubs.o

# AArch64 CWE-369 fixture: exercises the arch-aware divide-by-zero check. The
# divisor is the third operand of `sdiv`/`udiv` (`sdiv Wd, Wn, Wm` -> Wm); an
# unguarded division (no `cbz`/`cbnz` on the divisor and no `cmp`/`tst` +
# `b.<cond>` before it) co-located with an input source (`fgets`/`atoi`) is the
# CWE-369 site. The safe companion guards the divisor (`cbnz`/`cmp`) and must
# not fire. Same freestanding cross-build recipe as the others.
cwe369-aarch64-vuln: cwe369-aarch64-vuln.c cwe369-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe369-aarch64-vuln.c -o cwe369-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe369-aarch64-stubs.c -o cwe369-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe369-aarch64-vuln.o cwe369-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe369-aarch64-vuln.o cwe369-aarch64-stubs.o

# AArch64 CWE-119 fixture: exercises the arch-aware register-level buffer
# over-read/write check. The int index is sign-extended (`ldrsw x10, [sp, #N]`),
# the buffer address is formed with an explicit base+index sum (`add x9, x9,
# x10`), and the store dereferences that base register (`strb w8, [x9]`) with no
# preceding bounds check. The safe companion range-checks the index
# (`tbnz`/`subs` + `b.<cond>`) and must not fire. Same freestanding cross-build
# recipe as the others.
cwe119-aarch64-vuln: cwe119-aarch64-vuln.c cwe119-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe119-aarch64-vuln.c -o cwe119-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe119-aarch64-stubs.c -o cwe119-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe119-aarch64-vuln.o cwe119-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe119-aarch64-vuln.o cwe119-aarch64-stubs.o

# AArch64 CWE-787 fixture: exercises the arch-aware heap-OOB-write check. The
# malloc + memcpy co-location pattern is the same shape as the x86_64 fixture;
# the AAPCS64 length register `x2`/`w2` is loaded from a stack slot
# (`ldr w2, [sp, #N]`) for the tainted-length copy in `copy_to_heap()` (must
# fire), while the safe companion `safe_copy()` materializes a compile-time
# literal length with `mov w2, #0x3f` before `bl strncpy` (must NOT fire — the
# literal-length suppression catches it). Same freestanding cross-build recipe
# as the others.
cwe787-aarch64-vuln: cwe787-aarch64-vuln.c cwe787-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe787-aarch64-vuln.c -o cwe787-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe787-aarch64-stubs.c -o cwe787-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe787-aarch64-vuln.o cwe787-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe787-aarch64-vuln.o cwe787-aarch64-stubs.o

# AArch64 CWE-476 fixture: exercises the arch-aware NULL-pointer-dereference
# check. The allocator return register x0 is spilled to a stack slot
# (`str x0, [sp, #N]`), reloaded (`ldr xR, [sp, #N]`) and dereferenced through
# that base register (`str wzr, [xR]`) with no NULL-check; the safe companion
# guards the reloaded result with `cbz`/`cmp x0, #0` + `b.eq` (the AArch64
# guard recognizers must catch this and stay silent). Same freestanding
# cross-build recipe as the other AArch64 fixtures.
cwe476-aarch64-vuln: cwe476-aarch64-vuln.c cwe476-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe476-aarch64-vuln.c -o cwe476-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe476-aarch64-stubs.c -o cwe476-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe476-aarch64-vuln.o cwe476-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe476-aarch64-vuln.o cwe476-aarch64-stubs.o

clean:
	rm -f $(BINS) cwe78-aarch64-vuln cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o \
		cwe732-aarch64-vuln cwe732-aarch64-vuln.o cwe732-aarch64-stubs.o \
		cwe190-aarch64-vuln cwe190-aarch64-vuln.o cwe190-aarch64-stubs.o \
		cwe134-aarch64-vuln cwe134-aarch64-vuln.o cwe134-aarch64-stubs.o \
		cwe415-aarch64-vuln cwe415-aarch64-vuln.o cwe415-aarch64-stubs.o \
		cwe416-aarch64-vuln cwe416-aarch64-vuln.o cwe416-aarch64-stubs.o \
		cwe369-aarch64-vuln cwe369-aarch64-vuln.o cwe369-aarch64-stubs.o \
		cwe119-aarch64-vuln cwe119-aarch64-vuln.o cwe119-aarch64-stubs.o \
		cwe787-aarch64-vuln cwe787-aarch64-vuln.o cwe787-aarch64-stubs.o \
		cwe476-aarch64-vuln cwe476-aarch64-vuln.o cwe476-aarch64-stubs.o
