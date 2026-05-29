/*
 * CWE-676 fixture: Use of Potentially Dangerous Function.
 *
 * Calls inherently-unsafe libc functions whose very use is the weakness:
 *   - gets()    : no bound is expressible (removed from C11)  -> HIGH confidence
 *   - strcpy()  : unbounded copy                              -> MEDIUM
 *   - sprintf() : unbounded formatted write                   -> MEDIUM
 *
 * autopsy's CWE-676 check must flag each of these call sites. It must NOT flag
 * the bounded siblings (strncpy/snprintf/fgets) used in the clean baseline.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdio.h>
#include <string.h>

/* gets() was removed from C11/glibc headers; declare it so the call site still
 * resolves to the `gets` symbol (linked from libc) that autopsy must flag. */
extern char *gets(char *s);

int main(void) {
    char dst[16];
    char line[64];

    gets(line);              /* CWE-676: gets() has no bound at all */

    strcpy(dst, line);       /* CWE-676: unbounded string copy */

    char msg[32];
    sprintf(msg, "got: %s", dst);  /* CWE-676: unbounded formatted write */

    puts(msg);
    return 0;
}
