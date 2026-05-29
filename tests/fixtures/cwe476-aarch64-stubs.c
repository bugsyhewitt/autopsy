/* Stub libc/runtime for the freestanding AArch64 CWE-476 fixture.
 *
 * Provides minimal definitions of the imported symbols (malloc, getenv,
 * strlen, fgets, atoi) and a static _start entry so cwe476-aarch64-vuln.c
 * links into a complete, statically-linked AArch64 ELF without a sysroot. The
 * stub bodies have no bearing on detection — autopsy resolves the ``bl`` call
 * targets back to the symbol names malloc/getenv/strlen and inspects the
 * spill/reload/guard pattern around the x0 result register. See REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

/* A non-folding allocator stub: returns a fixed non-NULL pointer so the
 * caller path that reaches the dereference stays live in the codegen. */
void *malloc(size_t size) { static char heap[256]; (void)size; return heap; }

/* getenv stub: returns the static buffer (non-NULL) so the safe_env() path
 * that reaches strlen() stays live in the codegen. */
char *getenv(const char *name) { static char buf[16] = "/home/test"; (void)name; return buf; }

/* strlen stub: byte-counting loop. Only the call-site presence matters. */
size_t strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

/* A non-folding input stub: returns its buffer (non-NULL) so the caller path
 * that reaches atoi() stays live in the codegen. */
char *fgets(char *s, int size, void *stream) { (void)size; (void)stream; return s; }

/* Returns a runtime-derived (non-constant) value so the compiler cannot fold
 * the atoi/malloc chain away; the actual value is irrelevant. */
int atoi(const char *nptr) { return nptr ? (int)(unsigned char)nptr[0] : 0; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
