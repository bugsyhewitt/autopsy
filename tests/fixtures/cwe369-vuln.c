/*
 * CWE-369 fixture: divide by zero driven by attacker-controlled input.
 *
 * The vulnerable function divides a fixed numerator by a divisor that comes
 * straight from user input with NO zero-check. An attacker who supplies "0"
 * drives the idiv to a divide-error exception (SIGFPE), crashing the process.
 * autopsy must flag the unguarded division co-located with the input source.
 *
 * The safe function performs the same division but guards the divisor with an
 * `if (d == 0)` check first — autopsy must NOT flag it (zero false positives).
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>

/* The vulnerable sink: divide with NO zero-check on the input divisor. */
int risky_ratio(int total, int divisor) {
    return total / divisor;      /* SIGFPE when divisor == 0 (unguarded) */
}

/* Safe companion: the divisor is checked before the divide. Must NOT fire. */
int safe_ratio(int total, int divisor) {
    if (divisor == 0) {          /* zero-check guard */
        return 0;
    }
    return total / divisor;
}

int main(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int divisor = atoi(line);    /* tainted: attacker controls the divisor */
    int r1 = risky_ratio(1000, divisor);
    int r2 = safe_ratio(1000, divisor);
    printf("%d %d\n", r1, r2);
    return 0;
}
