/*
 * Clean baseline fixture: contains NONE of the four vulnerability classes.
 *
 * - No attacker-controlled offset into a buffer (CWE-119): index is clamped.
 * - No overflowing allocation size (CWE-190): fixed-size allocation.
 * - No use-after-free (CWE-416): pointer is used only before free.
 * - No system()/execve() call at all (CWE-78).
 *
 * autopsy must report ZERO findings against this binary.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char buf[16];

int main(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int idx = atoi(line);
    if (idx < 0 || idx >= (int)sizeof(buf)) {  /* bounds checked: safe */
        idx = 0;
    }
    buf[idx] = 'A';

    char *p = malloc(64);                       /* fixed, non-overflowing size */
    if (p) {
        strncpy(p, line, 63);
        p[63] = '\0';
        printf("%s", p);                        /* used before free */
        free(p);
    }
    return 0;
}
