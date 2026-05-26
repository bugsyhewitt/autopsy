/*
 * CWE-416 fixture: use-after-free, INTRA-PROCEDURAL.
 *
 * malloc, free, and the use of the freed pointer all live in the same function
 * body with no function calls between the free and the use. This keeps the
 * analysis intra-procedural per the v0.1 criteria: autopsy tracks the freed
 * allocation within one function's CFG and flags the later dereference.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(32);        /* allocation */
    if (!p) {
        return 1;
    }
    strcpy(p, "hello");
    free(p);                     /* free path */

    /* No function calls between the free above and the use below. */
    p[0] = 'X';                  /* use-after-free: write to freed memory */
    int c = p[0];                /* use-after-free: read from freed memory */

    return c;
}
