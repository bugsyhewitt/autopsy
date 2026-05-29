/*
 * CWE-476 fixture: NULL pointer dereference of an unchecked allocator result.
 *
 * The vulnerable function allocates a buffer with malloc() and immediately
 * writes through the returned pointer with NO NULL-check. When the allocation
 * fails malloc() returns NULL and the store faults on the zero page (SIGSEGV).
 * autopsy must flag the unchecked dereference of the malloc() result.
 *
 * The safe companion performs the same allocation but guards the result with
 * an `if (!p) return;` NULL-check before using it — autopsy must NOT flag it
 * (zero false positives). A second safe companion checks getenv()'s result
 * before dereferencing it.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The vulnerable sink: dereference the malloc() result with NO NULL-check. */
int risky_fill(int n) {
    int *p = malloc(n * sizeof(int));
    p[0] = 42;                 /* SIGSEGV if malloc returned NULL (unchecked) */
    return p[0];
}

/* Safe companion: the result is NULL-checked before use. Must NOT fire. */
int safe_fill(int n) {
    int *p = malloc(n * sizeof(int));
    if (p == NULL) {           /* NULL-check guard */
        return -1;
    }
    p[0] = 42;
    return p[0];
}

/* Safe companion: getenv() result checked before dereference. Must NOT fire. */
size_t safe_env(void) {
    char *home = getenv("HOME");
    if (!home) {               /* NULL-check guard */
        return 0;
    }
    return strlen(home);
}

int main(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int n = atoi(line);
    int r1 = risky_fill(n);
    int r2 = safe_fill(n);
    size_t r3 = safe_env();
    printf("%d %d %zu\n", r1, r2, r3);
    return 0;
}
