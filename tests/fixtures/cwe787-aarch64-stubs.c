/* Stub libc/runtime for the freestanding AArch64 CWE-787 fixture.
 *
 * Provides minimal definitions of the imported symbols (malloc, free, memcpy,
 * strncpy, fgets, atoi) and a static _start entry so cwe787-aarch64-vuln.c links
 * into a complete, statically-linked AArch64 ELF without a sysroot. The stub
 * bodies have no bearing on detection — autopsy resolves the `bl` call targets
 * back to the symbol names malloc/memcpy/strncpy/fgets/atoi and reads the copy
 * length out of the AAPCS64 argument register (x2/w2) at each call site. See
 * REGENERATE.md.
 */
typedef unsigned long size_t;

/* `stdin` is referenced by the fixture's fgets() calls; a single byte of
   storage is enough for the freestanding link (its value is never used). */
char _stdin_storage;
void *stdin = &_stdin_storage;

/* -O0 codegen lowers `char src[256] = {0}` to a memset call; provide it. */
void *memset(void *s, int c, size_t n)
{
    char *p = (char *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (char)c;
    }
    return s;
}

static char heap[4096];
static size_t heap_off;

void *malloc(size_t size)
{
    if (heap_off + size > sizeof(heap)) {
        return 0;
    }
    void *p = &heap[heap_off];
    heap_off += size;
    return p;
}

void free(void *ptr) { (void)ptr; }

void *memcpy(void *dst, const void *src, size_t n)
{
    char *d = (char *)dst;
    const char *s = (const char *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i]; i++) {
        dst[i] = src[i];
    }
    for (; i < n; i++) {
        dst[i] = 0;
    }
    return dst;
}

char *fgets(char *s, int size, void *stream)
{
    (void)stream;
    if (size > 0) {
        s[0] = 0;
    }
    return s;
}

int atoi(const char *nptr) { return nptr ? (int)nptr[0] : 0; }

void _start(void)
{
    extern int main(void);
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
