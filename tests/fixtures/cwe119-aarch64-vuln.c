/* CWE-119 (buffer over-read/write via attacker-controlled index) fixture for
 * AArch64 (ARM64).
 *
 * Mirrors cwe119-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-119 check on AArch64. The
 * scanner finds a scaled-index memory access (a load/store whose *index* is a
 * register-held, attacker-derived value) that is NOT preceded by a bounds-check
 * compare/branch, and reports it when an attacker-controlled input source is
 * also present in the binary.
 *
 * On AArch64 a `buf[idx]` access at -O0 compiles to a register-offset
 * load/store: the int index is sign-extended (`sxtw x<n>, w<n>`) and used as the
 * offset operand of an `ldr`/`str`/`ldrb`/`strb` against the buffer base —
 * e.g. `ldrb w0, [x1, x2]` or `str w0, [x1, x2, lsl #2]`. The sign-extension is
 * the AArch64 analogue of the x86_64 `movsxd`/`cdqe` index-promotion idiom, and
 * the register index is the genuinely data-dependent ("symbolic") offset that
 * makes the access high-confidence.
 *
 *   - store_at(): buf[idx] = value with NO bounds check on idx   [VULN, high]
 *   - safe_store(): if (idx < 0 || idx >= 16) return; buf[idx]=…  [SAFE, silent]
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of fgets/atoi/printf/_start in cwe119-aarch64-stubs.c. The
 * host is x86_64, so a full AArch64 libc/sysroot is not available; the
 * freestanding form lets a plain `clang --target=aarch64-linux-gnu` build a
 * well-formed, loadable AArch64 ELF whose `bl` targets resolve to the symbol
 * names fgets/atoi (the attacker-input source the check requires). The detection
 * signal is the unguarded register-indexed store co-located with those input
 * source call sites. See REGENERATE.md.
 *
 * Keep the index coming from a function parameter (so it lands in a register the
 * compiler does not fold to a constant) and keep safe_store()'s range check
 * intact, so the vulnerable/safe split holds.
 */
typedef unsigned long size_t;

char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);
int printf(const char *fmt, ...);

static char buf[16];

/* The vulnerable sink: writes to buf[idx] where idx is attacker-controlled and
 * is NOT bounds-checked. VULN. */
void store_at(int idx, char value)
{
    buf[idx] = value;            /* str/strb with an unchecked register index: CWE-119 */
}

/* Safe companion: the index is range-checked before the access. Must NOT fire. */
void safe_store(int idx, char value)
{
    if (idx < 0 || idx >= 16) {  /* bounds-check guard (cmp + b.<cond>) */
        return;
    }
    buf[idx] = value;
}

int main(void)
{
    char line[64];
    void *stdin_stub = 0;
    if (!fgets(line, sizeof(line), stdin_stub)) {
        return 0;
    }
    int idx = atoi(line);        /* tainted: attacker controls the index */
    store_at(idx, 'A');          /* reaches the OOB sink */
    safe_store(idx, 'B');        /* guarded: must not be flagged */
    printf("%c\n", buf[0]);
    return 0;
}
