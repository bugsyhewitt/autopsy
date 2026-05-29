/* Stub libc/runtime for the freestanding AArch64 CWE-732 fixture.
 *
 * Provides minimal definitions of the imported symbols (chmod, umask) and a
 * static _start entry so cwe732-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names chmod/umask and reads the mode/mask immediate from the argument
 * register at each call site. See REGENERATE.md.
 */
typedef unsigned int mode_t;
extern int main(void);

int chmod(const char *path, mode_t mode) { return (path && mode) ? 0 : -1; }
int umask(mode_t mask) { return (int)mask; }

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
