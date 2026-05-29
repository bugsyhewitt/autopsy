/* CWE-369 (divide-by-zero) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe369-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-369 check on AArch64. The
 * scanner finds integer-division instructions (`sdiv`/`udiv`) whose divisor —
 * the THIRD operand (`sdiv Wd, Wn, Wm` -> Wm) — is not guarded by a preceding
 * zero-check, and reports them when an attacker-controlled input source is also
 * present in the binary. The guard idioms it excludes are `cbz`/`cbnz` on the
 * divisor and `cmp`/`tst` + `b.<cond>`.
 *
 *   - risky_ratio(): total / divisor with NO zero-check  [VULN, medium]
 *   - safe_ratio():  if (divisor == 0) return 0; ... /    [SAFE, silent]
 *
 * ARMv8 defines integer divide-by-zero as producing 0 (it does NOT trap like
 * x86_64's #DE/SIGFPE), so on AArch64 the unguarded divide is a silently-wrong
 * result an attacker can force rather than a crash — but the missing zero-check
 * is still the CWE-369 weakness, and autopsy flags it identically.
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of fgets/atoi/printf/_start in cwe369-aarch64-stubs.c. The
 * host is x86_64, so a full AArch64 libc/sysroot is not available; the
 * freestanding form lets a plain `clang --target=aarch64-linux-gnu` build a
 * well-formed, loadable AArch64 ELF whose `bl` targets resolve to the symbol
 * names fgets/atoi (the attacker-input source the check requires). The detection
 * signal is the unguarded `sdiv` co-located with those input-source call sites.
 * See REGENERATE.md.
 *
 * Keep the divisor coming from a function parameter (so it lands in a register
 * the compiler does not fold to a constant) and keep safe_ratio()'s zero-check
 * intact, so the vulnerable/safe split holds.
 */
typedef unsigned long size_t;

char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);
int printf(const char *fmt, ...);

/* The vulnerable sink: divide with NO zero-check on the input divisor. VULN. */
int risky_ratio(int total, int divisor)
{
    return total / divisor;      /* sdiv with unguarded divisor: CWE-369 */
}

/* Safe companion: the divisor is checked before the divide. Must NOT fire. */
int safe_ratio(int total, int divisor)
{
    if (divisor == 0) {          /* zero-check guard (cbz / cmp+b.eq) */
        return 0;
    }
    return total / divisor;
}

int main(void)
{
    char line[64];
    void *stdin_stub = 0;
    if (!fgets(line, sizeof(line), stdin_stub)) {
        return 0;
    }
    int divisor = atoi(line);    /* tainted: attacker controls the divisor */
    int r1 = risky_ratio(1000, divisor);
    int r2 = safe_ratio(1000, divisor);
    printf("%d %d\n", r1, r2);
    return 0;
}
