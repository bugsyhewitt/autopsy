/* Stub libc/runtime for the freestanding AArch64 CWE-787 fixture.
 *
 * Provides minimal definitions of the imported symbols (malloc, free, memcpy,
 * strncpy, fgets, atoi) and a static _start entry so cwe787-aarch64-vuln.c
 * links into a complete, statically-linked AArch64 ELF without a sysroot. The
 * stub bodies have no bearing on detection — autopsy resolves the `bl` call
 * targets back to the symbol names malloc/memcpy/strncpy/fgets/atoi and
 * inspects the length-argument register (`x2`/`w2`) at the copy-call site.
 * See REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

/* A non-folding allocator stub: returns a fixed non-NULL pointer so the
 * caller path that reaches memcpy/strncpy stays live in the codegen. */
void *malloc(size_t size) { static char heap[256]; (void)size; return heap; }

/* No-op free; only the call-site presence matters. */
void free(void *ptr) { (void)ptr; }

/* Minimal memcpy/strncpy: byte loop. The semantics are irrelevant; only the
 * length-argument register convention (w2/x2 on AAPCS64) matters. */
void *memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];
        if (src[i] == 0) {
            for (size_t j = i + 1; j < n; j++) dst[j] = 0;
            return dst;
        }
    }
    return dst;
}

/* A non-folding input stub: returns its buffer (non-NULL) so the caller path
 * that reaches atoi() stays live in the codegen. */
char *fgets(char *s, int size, void *stream) { (void)size; (void)stream; return s; }

/* Returns a runtime-derived (non-constant) value so the compiler cannot fold
 * the atoi/malloc/memcpy chain away; the actual value is irrelevant. */
int atoi(const char *nptr) { return nptr ? (int)(unsigned char)nptr[0] : 0; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
