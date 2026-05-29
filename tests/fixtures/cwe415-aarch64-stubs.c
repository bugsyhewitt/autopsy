/* Stub libc/runtime for the freestanding AArch64 CWE-415 fixture.
 *
 * Provides minimal definitions of the imported symbols (malloc, free) and a
 * static _start entry so cwe415-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names malloc/free and tracks the pointer through the stack slot at the
 * call sites. See REGENERATE.md.
 */
typedef unsigned long size_t;
extern int main(void);

/* A non-folding allocator stub: returns a fixed non-NULL pointer. */
void *malloc(size_t size) { static char heap[64]; (void)size; return heap; }

/* No-op free; the double-free signal is the two call sites, not the behavior. */
void free(void *ptr) { (void)ptr; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
