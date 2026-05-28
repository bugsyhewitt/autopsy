/*
 * CWE-134 fixture: use of an externally-controlled format string.
 *
 * The program reads a line from stdin (attacker-controlled) and passes it
 * DIRECTLY as the format string of printf(). Because the attacker controls the
 * format string, they can inject conversion specifiers (%x, %n, %s) to leak
 * stack memory or write to arbitrary addresses. autopsy must show the tainted
 * buffer reaching printf()'s format-string argument, which is NOT a literal.
 *
 * The safe companion log_line() shows the correct usage — a constant format
 * string with the user data as a %s argument — and must NOT be flagged.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SAFE: constant format string, user data passed as a %s argument. */
void log_line(const char *user) {
    printf("log: %s\n", user);   /* literal format -> not a finding */
}

/* VULNERABLE sink: the attacker-controlled buffer IS the format string. */
void emit(const char *user) {
    printf(user);                /* CWE-134: uncontrolled format string */
}

int main(void) {
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    line[strcspn(line, "\n")] = '\0';
    log_line(line);              /* safe use */
    emit(line);                  /* tainted input becomes the format string */
    return 0;
}
