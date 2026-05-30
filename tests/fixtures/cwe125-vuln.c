/*
 * CWE-125 fixture: out-of-bounds heap read via malloc + memcmp taint mismatch.
 *
 * The program reads two independent values from stdin: a size for malloc and a
 * length for memcmp.  When size and length are independent tainted values,
 * memcmp may read beyond the end of the heap allocation -- an out-of-bounds
 * heap read (CWE-125).  This is the read-side complement of the cwe787 fixture.
 *
 * The safe_compare() companion uses a compile-time literal length (4 bytes)
 * and must NOT fire, because the read extent is fixed and cannot be
 * attacker-controlled.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The vulnerable pattern: malloc(size), memcmp(buf, needle, length) where
   size and length are independent attacker-controlled values.  If length
   exceeds size, memcmp walks past the end of the heap buffer. */
int compare_from_heap(int size, int length) {
    char *buf = malloc(size);   /* allocation size is tainted */
    if (!buf) return -1;
    memset(buf, 0, size > 0 ? 1 : 0);
    char needle[256] = {0};
    int rc = memcmp(buf, needle, length); /* read length is independently tainted */
    free(buf);
    return rc;
}

/* Safe companion: literal-length memcmp on a heap buffer.  The 4-byte read
   extent is a compile-time constant and cannot be attacker-controlled, so
   CWE-125's literal-length suppression must drop this. */
int safe_compare(int size) {
    char *buf = malloc(size);
    if (!buf) return -1;
    char magic[4] = {'A','U','T','O'};
    int rc = memcmp(buf, magic, 4); /* literal length 4 -> suppressed */
    free(buf);
    return rc;
}

int main(void) {
    char line[64];
    int alloc_size, cmp_len;

    if (!fgets(line, sizeof(line), stdin)) return 0;
    alloc_size = atoi(line);    /* tainted: attacker controls allocation size */

    if (!fgets(line, sizeof(line), stdin)) return 0;
    cmp_len = atoi(line);       /* tainted: attacker controls compare length */

    int r1 = compare_from_heap(alloc_size, cmp_len);
    int r2 = safe_compare(alloc_size);
    return (r1 | r2) ? 0 : 0;
}
