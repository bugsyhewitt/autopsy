/*
 * CWE-190 fixture: integer overflow that propagates to the size argument of
 * an allocator.
 *
 * The program reads a count (attacker-controlled) and multiplies it by a
 * per-element size. On a 32-bit int the multiplication can overflow, yielding
 * a small allocation that the caller then treats as large. autopsy must show
 * the tainted value flowing through an arithmetic op into malloc's size arg.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The vulnerable sink: malloc sized by an overflowing multiply. */
void *alloc_records(int count) {
    int bytes = count * 4096;    /* overflows for large count -> small size */
    return malloc(bytes);        /* allocator fed an overflowed size */
}

int main(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int count = atoi(line);      /* tainted: attacker controls count */
    void *p = alloc_records(count);
    if (p) {
        memset(p, 0, 4096);      /* writes 4096 even when allocation was tiny */
        free(p);
    }
    return 0;
}
