/*
 * CWE-78 fixture: OS command injection where tainted input reaches system().
 *
 * The program reads a string from stdin (attacker-controlled), concatenates it
 * into a shell command, and passes it to system(). autopsy must show the
 * tainted buffer flowing into the argument of system()/execve().
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The vulnerable sink: system() called with attacker-influenced command. */
void run_cmd(const char *user) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %s", user);  /* tainted concat */
    system(cmd);                                   /* command injection sink */
}

int main(void) {
    char line[96];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    line[strcspn(line, "\n")] = '\0';
    run_cmd(line);               /* tainted input reaches system() */
    return 0;
}
