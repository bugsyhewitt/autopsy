/*
 * CWE-377 fixture: Insecure Temporary File.
 *
 * Calls race-prone libc temporary-file functions whose contract leaves a
 * time-of-check-to-time-of-use (TOCTOU) window: they hand back a *name* without
 * atomically creating the file, so an attacker can pre-create the path between
 * name generation and the program's open().
 *   - tmpnam()  : returns a name, no atomic create  -> MEDIUM confidence
 *   - mktemp()  : expands a template to a name only  -> MEDIUM
 *   - tempnam() : TMPDIR-aware but same race         -> MEDIUM
 *
 * autopsy's CWE-377 check must flag each of these call sites. It must NOT flag
 * the atomic create-and-open replacement mkstemp() used by safe_create().
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* tmpnam/tempnam/mktemp are marked obsolescent and may be hidden behind feature
 * guards; declare them so the call sites resolve to the libc symbols autopsy
 * must flag. */
extern char *tmpnam(char *s);
extern char *tempnam(const char *dir, const char *pfx);
extern char *mktemp(char *template);

void make_temp(void) {
    char name[L_tmpnam];
    tmpnam(name);            /* CWE-377: name only, no atomic create */
    FILE *f = fopen(name, "w");
    if (f) {
        fputs("data\n", f);
        fclose(f);
    }
}

void make_template(void) {
    char tmpl[] = "/tmp/autopsyXXXXXX";
    char *p = mktemp(tmpl);  /* CWE-377: expands template to a name only */
    FILE *f = fopen(p, "w");
    if (f) fclose(f);
}

void make_tempnam(void) {
    char *p = tempnam("/tmp", "ap");  /* CWE-377: TMPDIR-aware, same race */
    if (p) {
        FILE *f = fopen(p, "w");
        if (f) fclose(f);
        free(p);
    }
}

/* The safe form: mkstemp() atomically creates and opens with O_CREAT|O_EXCL.
 * autopsy must NOT flag this. */
void safe_create(void) {
    char tmpl[] = "/tmp/autopsyXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) close(fd);
}

int main(void) {
    make_temp();
    make_template();
    make_tempnam();
    safe_create();
    return 0;
}
