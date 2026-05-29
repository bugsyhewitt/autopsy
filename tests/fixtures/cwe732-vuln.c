/*
 * CWE-732 fixture: Incorrect Permission Assignment for Critical Resource.
 *
 * - expose_secret():  chmod(path, 0777)  -> world-writable (group+world write) [VULN]
 * - widen_shared():   chmod(path, 0666)  -> group+world write                  [VULN]
 * - loose_umask():    umask(0)           -> masks nothing; created files can be
 *                                            group/world writable               [VULN]
 * - lock_down():      chmod(path, 0600)  -> owner-only; must NOT fire           [SAFE]
 * - tight_umask():    umask(0077)        -> strips all group/other; NOT fire    [SAFE]
 *
 * autopsy must flag the three vulnerable mode/mask literals and stay silent on
 * the two restrictive ones (zero false positives).
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <sys/stat.h>
#include <sys/types.h>

/* World-writable: 0777 sets the world-write bit (0o002). VULNERABLE. */
int expose_secret(const char *path) {
    return chmod(path, 0777);
}

/* Group+world readable/writable: 0666 sets group-write and world-write. VULNERABLE. */
int widen_shared(const char *path) {
    return chmod(path, 0666);
}

/* umask(0) masks nothing -> new files keep group/world write. VULNERABLE. */
void loose_umask(void) {
    umask(0);
}

/* Owner read/write only: restrictive, must NOT be flagged. SAFE. */
int lock_down(const char *path) {
    return chmod(path, 0600);
}

/* Strips all group/other permission bits: restrictive, must NOT fire. SAFE. */
void tight_umask(void) {
    umask(0077);
}

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/tmp/data";
    tight_umask();
    loose_umask();
    lock_down(path);
    expose_secret(path);
    widen_shared(path);
    return 0;
}
