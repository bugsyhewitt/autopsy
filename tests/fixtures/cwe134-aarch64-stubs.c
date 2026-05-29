/* Stub libc/runtime for the freestanding AArch64 CWE-134 fixture.
 *
 * Provides minimal definitions of the imported symbols (printf, fprintf, fgets)
 * and a static _start entry so cwe134-aarch64-vuln.c links into a complete,
 * statically-linked AArch64 ELF without a sysroot. The stub bodies have no
 * bearing on detection — autopsy resolves the `bl` call targets back to the
 * symbol names printf/fprintf/fgets and inspects the format-argument register's
 * provenance at each call site. See REGENERATE.md.
 */
typedef unsigned long size_t;
typedef __builtin_va_list va_list;
extern int main(void);

int printf(const char *fmt, ...) { return fmt ? 1 : 0; }
int fprintf(void *stream, const char *fmt, ...) { return (stream && fmt) ? 1 : 0; }

char *fgets(char *s, int size, void *stream)
{
    /* Pretend a single newline was read so callers see a non-NULL result. */
    if (size > 0 && s && stream) {
        s[0] = '\n';
        if (size > 1) {
            s[1] = '\0';
        }
        return s;
    }
    return (char *)0;
}

void _start(void)
{
    main();
    /* exit(0) via the AArch64 exit syscall (no libc available) */
    register long x8 __asm__("x8") = 93;  /* __NR_exit */
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0" :: "r"(x8), "r"(x0));
}
