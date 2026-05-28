/*
 * CWE-416 fixture: use-after-free, SINGLE-HOP INTERPROCEDURAL.
 *
 * The freeing code and the dangling dereference live in DIFFERENT functions:
 *
 *   release(p)  frees its incoming pointer argument.
 *   run()       allocates a buffer, hands it to release(), then dereferences
 *               the now-dangling pointer after release() returns.
 *
 * This is the single-hop cross-function pattern the interprocedural CWE-416
 * pass detects (POST_V01 Tier 2 #4): caller passes a pointer to a callee that
 * frees it, then uses the freed pointer with no intervening call.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Callee: frees the pointer handed to it by its caller. */
void release(char *p) {
    free(p);                     /* free path — frees the caller's pointer */
}

/* Caller: allocates, passes to release(), then uses the dangling pointer. */
int run(void) {
    char *buf = malloc(64);      /* allocation */
    if (!buf) {
        return 1;
    }
    strcpy(buf, "data");

    release(buf);                /* pointer freed inside the callee */

    /* No function calls between release() returning and the use below. */
    buf[0] = 'Z';                /* use-after-free across the call boundary */
    return buf[0];
}

int main(void) {
    return run();
}
