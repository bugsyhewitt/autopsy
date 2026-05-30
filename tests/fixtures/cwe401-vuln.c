/*
 * CWE-401 (Missing Release of Memory after Effective Lifetime) fixture.
 *
 * Exercises the intra-procedural memory-leak detector. The vulnerable
 * function allocates a heap buffer, uses it locally, and returns *without*
 * freeing it and without transferring ownership to anyone — the textbook
 * leak. The safe companions exercise every ownership-transfer path the
 * detector recognizes (free, return-the-pointer, pass-as-argument, store-to-
 * memory) — none of them must fire, which is what locks in the
 * zero-false-positive contract on the clean side.
 *
 * Compiled with the same flags as the rest of the fixtures (see Makefile):
 *   gcc -O0 -fno-stack-protector -no-pie -g
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Vulnerable: allocates, writes a few bytes, returns. The malloc'd buffer is
 * never freed, never returned, never passed out, never stored anywhere — it
 * leaks every time leaky() is called. */
void leaky(void) {
    char *p = (char *)malloc(64);
    if (p != NULL) {
        p[0] = 'x';
        p[1] = '\0';
    }
    /* no free(p); no return p; no escape. */
    return;
}

/* Safe via release: the allocation is freed before return. CWE-401 must
 * NOT fire here. */
void safe_free(void) {
    char *p = (char *)malloc(64);
    if (p != NULL) {
        p[0] = 'x';
        free(p);
    }
}

/* Safe via return: the allocation is returned to the caller, transferring
 * ownership. CWE-401 must NOT fire here. */
char *safe_return(void) {
    char *p = (char *)malloc(64);
    return p;
}

/* Safe via argument-pass: the allocation is handed to another function which
 * may take ownership. CWE-401 must NOT fire here. */
static void take_ownership(char *q) {
    /* Pretend to take ownership; the compiler can't tell either way. */
    (void)q;
}

void safe_handoff(void) {
    char *p = (char *)malloc(64);
    take_ownership(p);
}

/* Safe via memory-store: the allocation is stashed into a global, where the
 * program can later free it. CWE-401 must NOT fire here. */
static char *g_stash;

void safe_stash(void) {
    char *p = (char *)malloc(64);
    g_stash = p;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    leaky();
    safe_free();
    char *r = safe_return();
    free(r);
    safe_handoff();
    safe_stash();
    free(g_stash);
    return 0;
}
