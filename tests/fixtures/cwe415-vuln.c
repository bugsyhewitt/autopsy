/*
 * CWE-415 fixture: double-free, INTRA-PROCEDURAL.
 *
 * malloc and both free() calls live in the same function body with no
 * function calls between the first free and the second free. This keeps
 * the analysis intra-procedural per the v0.1 criteria: autopsy tracks the
 * freed allocation within one function's CFG and flags the second free.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(32);        /* allocation */
    if (!p) {
        return 1;
    }
    strcpy(p, "hello");
    free(p);                     /* first free */

    /* No function calls between the first free above and the second free below. */
    free(p);                     /* double-free: CWE-415 */

    return 0;
}
