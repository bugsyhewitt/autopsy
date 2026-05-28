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

SRCS := cwe119-vuln.c cwe190-vuln.c cwe415-vuln.c cwe416-vuln.c cwe416-interproc-vuln.c cwe78-vuln.c cwe787-vuln.c clean-baseline.c
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

aarch64: cwe78-aarch64-vuln

cwe78-aarch64-vuln: cwe78-aarch64-vuln.c cwe78-aarch64-stubs.c
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe78-aarch64-vuln.c -o cwe78-aarch64-vuln.o
	$(AARCH64_CC) $(AARCH64_TARGET) $(AARCH64_CFLAGS) -c cwe78-aarch64-stubs.c -o cwe78-aarch64-stubs.o
	$(AARCH64_LD) -o $@ cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o -e _start --no-dynamic-linker
	rm -f cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o

clean:
	rm -f $(BINS) cwe78-aarch64-vuln cwe78-aarch64-vuln.o cwe78-aarch64-stubs.o
