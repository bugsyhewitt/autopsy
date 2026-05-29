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

SRCS := cwe119-vuln.c cwe190-vuln.c cwe338-vuln.c cwe367-vuln.c cwe369-vuln.c cwe377-vuln.c cwe415-vuln.c cwe415-interproc-vuln.c cwe416-vuln.c cwe416-interproc-vuln.c cwe476-vuln.c cwe78-vuln.c cwe134-vuln.c cwe676-vuln.c cwe732-vuln.c cwe787-vuln.c clean-baseline.c
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

aarch64: cwe78-aarch64-vuln cwe732-aarch64-vuln cwe190-aarch64-vuln cwe134-aarch64-vuln

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

clean:
	rm -f $(BINS) cwe78-aarch64-vuln cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o \
		cwe732-aarch64-vuln cwe732-aarch64-vuln.o cwe732-aarch64-stubs.o \
		cwe190-aarch64-vuln cwe190-aarch64-vuln.o cwe190-aarch64-stubs.o \
		cwe134-aarch64-vuln cwe134-aarch64-vuln.o cwe134-aarch64-stubs.o
