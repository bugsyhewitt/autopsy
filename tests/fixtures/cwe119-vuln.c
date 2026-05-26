/*
 * CWE-119 fixture: buffer over-read/write via reachable memory access with
 * an attacker-controlled offset.
 *
 * The program reads an integer index from stdin (attacker-controlled, hence
 * "tainted") and writes into a fixed-size stack buffer at that index with no
 * bounds check. angr-backed whole-program analysis must reach the store
 * instruction with a symbolic (tainted) address.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char buf[16];

/* The vulnerable sink: writes to buf[idx] where idx comes from input. */
void store_at(int idx, char value) {
    buf[idx] = value;            /* out-of-bounds write when idx >= 16 or < 0 */
}

int main(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int idx = atoi(line);        /* tainted: attacker controls idx */
    store_at(idx, 'A');          /* reaches the OOB sink */
    printf("%c\n", buf[0]);
    return 0;
}
