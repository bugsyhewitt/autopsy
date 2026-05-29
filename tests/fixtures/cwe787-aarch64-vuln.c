/* CWE-787 (out-of-bounds heap write) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe787-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's CWE-787 check on AArch64. The check is a
 * call-site-driven co-location heuristic (malloc + a bulk-copy sink in the same
 * function, with an attacker-input source in the program); its only
 * register-level dependency is the length-literal resolver
 * `copy_call_length_is_literal`, which on AArch64 reads the AAPCS64 length
 * argument out of x2/w2:
 *
 *   memcpy(buf, src, length)  ->  ldr w2, [x29, #N]   (length reloaded from a
 *                                                       tainted stack slot ->
 *                                                       NOT a literal -> flagged)
 *
 *   safe_copy strncpy(p, line, 63)  ->  mov w2, #0x3f (length is a compile-time
 *                                                       immediate -> literal ->
 *                                                       suppressed, zero FP)
 *
 * The attacker controls both the malloc size and the memcpy length via
 * fgets()+atoi(), so the copy length is independently tainted and may exceed the
 * allocation — exactly the pattern the x86_64 fixture exercises.
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of fgets/atoi/malloc/free/memcpy/strncpy/_start in
 * cwe787-aarch64-stubs.c. The host is x86_64, so a full AArch64 libc/sysroot is
 * not available; the freestanding form lets a plain
 * `clang --target=aarch64-linux-gnu` build a well-formed, loadable AArch64 ELF
 * whose `bl` targets resolve to the symbol names fgets/atoi/malloc/memcpy/
 * strncpy. autopsy resolves those names at the call sites, pairs the allocator
 * with the eligible (non-literal-length) copy sink in the same function, and
 * flags the out-of-bounds-write surface. See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the length-argument form matter.
 */
typedef unsigned long size_t;

void *malloc(size_t size);
void free(void *ptr);
void *memcpy(void *dst, const void *src, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);

extern void *stdin;

/* The vulnerable pattern: malloc(size), memcpy(dst, src, length) where size and
   length are independent attacker-controlled values. The memcpy length is
   reloaded from a stack slot (the spilled `length` parameter), so the
   length-literal resolver classes it non-literal and the co-location fires. */
void copy_to_heap(int size, int length)
{
    char *buf = malloc(size);              /* allocation size is tainted */
    if (!buf) {
        return;
    }
    char src[256] = {0};
    memcpy(buf, src, (size_t)length);      /* write length is independently tainted */
    free(buf);
}

/* The safe companion: malloc + a copy whose length is a compile-time immediate
   (63). A literal length cannot be attacker-controlled, so the resolver marks it
   literal and the co-location heuristic must NOT fire here (zero false positives). */
void safe_copy(const char *line)
{
    char *p = malloc(64);                  /* fixed allocation */
    if (!p) {
        return;
    }
    strncpy(p, line, 63);                  /* literal length -> suppressed */
    free(p);
}

int main(void)
{
    char line[64];
    int alloc_size, copy_len;

    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    alloc_size = atoi(line);               /* tainted: attacker controls size */

    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    copy_len = atoi(line);                 /* tainted: attacker controls length */

    copy_to_heap(alloc_size, copy_len);
    safe_copy(line);
    return 0;
}
