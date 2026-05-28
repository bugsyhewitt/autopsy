/*
 * CWE-415 fixture: double-free, single-hop INTERPROCEDURAL.
 *
 * The two free() calls live in different functions, one call hop apart:
 *
 *   run():       p = malloc(...); free(p);   // first free in the caller
 *                release(p);                 // pass the freed pointer to a
 *                                            // callee that frees it AGAIN
 *
 *   release(p):  free(p);                    // second free -> double-free
 *
 * This is distinct from the intra-procedural cwe415-vuln fixture (both frees
 * in one body) and from cwe416-interproc-vuln (a use-after-free: there the
 * second event is a dereference, here it is a second free()). autopsy detects
 * it call-graph-driven: release() frees its incoming argument, and run()
 * freed that same pointer before handing it over, with no reallocation in
 * between.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdlib.h>
#include <string.h>

/* Frees its incoming pointer argument. */
void release(char *p) {
    free(p);
}

void run(void) {
    char *p = malloc(32);        /* allocation */
    if (!p) {
        return;
    }
    strcpy(p, "hello");
    free(p);                     /* first free, in the caller */

    /* No reallocation of p between the first free and the handoff below. */
    release(p);                  /* callee frees p again -> double-free (CWE-415) */
}

int main(void) {
    run();
    return 0;
}
