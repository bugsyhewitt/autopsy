/* Stub libc/runtime for the freestanding AArch64 CWE-190 fixture.
 *
 * Provides minimal definitions of the imported symbols (malloc, fgets, atoi)
 * and a static _start entry so cwe190-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names malloc/fgets/atoi and pairs the attacker-input source with the
 * 32-bit size arithmetic preceding the malloc call. See REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

void *stdin = (void *)0;

/* A non-folding allocator stub: returns a fixed non-NULL pointer. */
void *malloc(size_t size) { static char heap[64]; (void)size; return heap; }

/* Reads nothing; returns its buffer so the caller proceeds to atoi(). */
char *fgets(char *s, int size, void *stream) { (void)size; (void)stream; return s; }

/* Returns a fixed value; the actual taint comes from the call-site pairing. */
int atoi(const char *nptr) { return nptr ? 1 : 0; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
