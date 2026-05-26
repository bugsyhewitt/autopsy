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

SRCS := cwe119-vuln.c cwe190-vuln.c cwe416-vuln.c cwe78-vuln.c clean-baseline.c
BINS := $(SRCS:.c=)

.PHONY: all clean

all: $(BINS)

%: %.c
	$(CC) $(ARCH) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)
