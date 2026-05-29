/* Stub libc/runtime for the freestanding AArch64 CWE-369 fixture.
 *
 * Provides minimal definitions of the imported symbols (fgets, atoi, printf)
 * and a static _start entry so cwe369-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names fgets/atoi (the attacker-input source) and finds the unguarded
 * `sdiv` in risky_ratio() at the disassembly level. See REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

/* A non-folding input stub: returns its buffer (non-NULL) so the caller path
 * that reaches atoi()/the division stays live in the codegen. */
char *fgets(char *s, int size, void *stream) { (void)size; (void)stream; return s; }

/* Returns a runtime-derived (non-constant) divisor so the compiler cannot fold
 * the division away; the actual value is irrelevant to detection. */
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
