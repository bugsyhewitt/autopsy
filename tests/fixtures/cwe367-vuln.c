/*
 * CWE-367 fixture: Time-of-check Time-of-use (TOCTOU) Race Condition.
 *
 * Each vulnerable function checks a path by name and then uses a path by name,
 * leaving a window an attacker can exploit (typically a symlink swap):
 *   - access_then_open()   : access(path, W_OK) then open(path)   -> classic
 *                            setuid privilege-escalation TOCTOU.
 *   - stat_then_fopen()    : stat(path) then fopen(path)          -> the file
 *                            inspected may differ from the one opened.
 *   - lstat_then_unlink()  : lstat(path) then unlink(path)        -> the entry
 *                            removed may differ from the one stat'd.
 *
 * autopsy's CWE-367 check must flag each of these. It must NOT flag the safe
 * descriptor-based pattern in safe_open_then_fstat(), which opens once and then
 * inspects the returned *file descriptor* (fstat on an fd, not a path), nor the
 * functions that only check (only_check) or only use (only_use) a path.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* TOCTOU: check writability by name, then open by name. */
void access_then_open(const char *path) {
    if (access(path, W_OK) == 0) {   /* time of check */
        int fd = open(path, O_WRONLY);  /* time of use: may be a swapped symlink */
        if (fd >= 0) {
            write(fd, "x", 1);
            close(fd);
        }
    }
}

/* TOCTOU: stat by name, then fopen by name. */
void stat_then_fopen(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {      /* time of check */
        FILE *f = fopen(path, "r");  /* time of use */
        if (f) fclose(f);
    }
}

/* TOCTOU: lstat by name, then unlink by name. */
void lstat_then_unlink(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0) {     /* time of check */
        unlink(path);                /* time of use */
    }
}

/* SAFE: open once, then inspect the returned descriptor. No path is re-resolved
 * after the open, so there is no TOCTOU window. autopsy must NOT flag this. */
void safe_open_then_fstat(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        fstat(fd, &st);              /* operates on the fd, not the path */
        close(fd);
    }
}

/* SAFE: a lone check with no following by-name use. */
int only_check(const char *path) {
    return access(path, R_OK);
}

/* SAFE: a lone use with no preceding check. */
void only_use(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    const char *p = argc > 1 ? argv[1] : "/tmp/autopsy-toctou";
    access_then_open(p);
    stat_then_fopen(p);
    lstat_then_unlink(p);
    safe_open_then_fstat(p);
    only_check(p);
    only_use(p);
    return 0;
}
