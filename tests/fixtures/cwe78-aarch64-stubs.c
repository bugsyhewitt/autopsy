/* Stub libc/runtime for the freestanding AArch64 CWE-78 fixture.
 *
 * Provides minimal definitions of the imported symbols (fgets, system, stdin)
 * and a static _start entry so cwe78-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets in run_cmd()
 * back to the symbol names fgets/system. See REGENERATE.md.
 */
typedef unsigned long size_t;
typedef struct _IO_FILE FILE;
FILE *stdin;
extern int main(void);

char *fgets(char *s, int n, FILE *f) { (void)n; (void)f; return s; }
int system(const char *cmd) { return cmd ? 0 : -1; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
