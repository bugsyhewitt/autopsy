/* Stub libc/runtime for the freestanding AArch64 CWE-119 fixture.
 *
 * Provides minimal definitions of the imported symbols (fgets, atoi, printf)
 * and a static _start entry so cwe119-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names fgets/atoi (the attacker-input source) and finds the unguarded
 * register-indexed store in store_at() at the disassembly level. See
 * REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

/* A non-folding input stub: returns its buffer (non-NULL) so the caller path
 * that reaches atoi()/the indexed store stays live in the codegen. */
char *fgets(char *s, int size, void *stream) { (void)size; (void)stream; return s; }

/* Returns a runtime-derived (non-constant) index so the compiler cannot fold
 * the access away; the actual value is irrelevant to detection. */
int atoi(const char *nptr) { return nptr ? (int)(unsigned char)nptr[0] : 0; }

int printf(const char *fmt, ...) { (void)fmt; return 0; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
