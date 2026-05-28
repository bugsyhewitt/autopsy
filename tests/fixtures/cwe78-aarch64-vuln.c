/* CWE-78 (OS command injection) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe78-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's AArch64 support: the call-site-driven
 * CWE-78 check must fire on a `bl` (branch-with-link) call to system() whose
 * argument originates from an attacker-controlled fgets() read.
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of fgets/system/_start in cwe78-aarch64-stubs.c. The host is
 * x86_64, so a full AArch64 libc/sysroot is not available; the freestanding
 * form lets a plain `clang --target=aarch64-linux-gnu` build a well-formed,
 * loadable AArch64 ELF whose `bl` targets resolve to the symbol names fgets and
 * system. autopsy resolves those names at the call sites — exactly the signal
 * the CWE-78 heuristic needs. See REGENERATE.md for the build recipe.
 *
 * The bodies of the stubbed sink/source are irrelevant to detection; only the
 * presence of the call sites and their resolvable symbol names matters.
 */
typedef unsigned long size_t;
typedef struct _IO_FILE FILE;
extern FILE *stdin;
char *fgets(char *s, int n, FILE *f);
int system(const char *cmd);

int run_cmd(void)
{
    char buf[64];
    fgets(buf, 64, stdin);   /* attacker-controlled input source */
    return system(buf);      /* command-execution sink           */
}

int main(void)
{
    return run_cmd();
}
