/*
 * CWE-22 fixture: path traversal where tainted input flows into fopen().
 *
 * The program reads a filename from stdin (attacker-controlled), concatenates
 * it onto a base directory prefix, and passes the unsanitized result to
 * fopen(). An attacker can supply "../../etc/passwd" to escape the intended
 * "/var/www/uploads/" directory. autopsy must flag the fopen() call site as
 * a CWE-22 finding. The program performs NO realpath()/canonicalize_file_name()
 * sanitization, so the suppression heuristic must NOT fire.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void serve_file(const char *user) {
    char path[256];
    snprintf(path, sizeof(path), "/var/www/uploads/%s", user);
    FILE *f = fopen(path, "r");       /* path-traversal sink */
    if (f) {
        fclose(f);
    }
}

int main(void) {
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    line[strcspn(line, "\n")] = '\0';
    serve_file(line);                  /* tainted input reaches fopen() */
    return 0;
}
