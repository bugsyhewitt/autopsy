/*
 * CWE-787 fixture: out-of-bounds heap write via malloc + memcpy taint mismatch.
 *
 * The program reads two independent values from stdin: a size for malloc and a
 * length for memcpy.  When size and length are independent tainted values, memcpy
 * may write beyond the end of the heap allocation.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The vulnerable pattern: malloc(size), memcpy(dst, src, length) where
   size and length are independent attacker-controlled values. */
void copy_to_heap(int size, int length) {
    char *buf = malloc(size);   /* allocation size is tainted */
    if (!buf) return;
    char src[256] = {0};
    memcpy(buf, src, length);   /* write length is independently tainted */
    free(buf);
}

int main(void) {
    char line[64];
    int alloc_size, copy_len;

    if (!fgets(line, sizeof(line), stdin)) return 0;
    alloc_size = atoi(line);    /* tainted: attacker controls allocation size */

    if (!fgets(line, sizeof(line), stdin)) return 0;
    copy_len = atoi(line);      /* tainted: attacker controls copy length */

    copy_to_heap(alloc_size, copy_len);
    return 0;
}
