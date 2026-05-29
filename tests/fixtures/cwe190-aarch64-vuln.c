/* CWE-190 (integer overflow into an allocator size) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe190-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-190 register-level check on
 * AArch64. The size is computed in a 32-bit register (the w-view, which
 * truncates and so is the integer-overflow surface) and then sign-extended into
 * the AAPCS64 first-argument register (x0) for the `bl` (branch-with-link) call
 * to malloc:
 *
 *   count * 4096   ->   lsl w8, w8, #0xc     (one register source + immediate
 *                                             shift -> medium confidence)
 *
 * An attacker controls `count` via fgets()+atoi(), so the multiply can overflow
 * to a small allocation that the caller then treats as large — exactly the
 * pattern the x86_64 fixture exercises with `shl eax, 0xc`.
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of fgets/atoi/malloc/_start in cwe190-aarch64-stubs.c. The
 * host is x86_64, so a full AArch64 libc/sysroot is not available; the
 * freestanding form lets a plain `clang --target=aarch64-linux-gnu` build a
 * well-formed, loadable AArch64 ELF whose `bl` targets resolve to the symbol
 * names fgets/atoi/malloc. autopsy resolves those names at the call sites,
 * pairs the attacker-input source (fgets/atoi) with the 32-bit size arithmetic
 * before the malloc call, and flags the overflow surface. See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the 32-bit size arithmetic matter.
 */
typedef unsigned long size_t;

void *malloc(size_t size);
char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);

extern void *stdin;

/* The vulnerable sink: malloc sized by an overflowing 32-bit multiply. */
void *alloc_records(int count)
{
    int bytes = count * 4096;    /* overflows for large count -> small size */
    return malloc(bytes);        /* allocator fed an overflowed size */
}

int main(void)
{
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    int count = atoi(line);      /* tainted: attacker controls count */
    void *p = alloc_records(count);
    return p ? 0 : 1;
}
