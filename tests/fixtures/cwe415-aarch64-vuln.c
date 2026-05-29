/* CWE-415 (double-free, intra-procedural) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe415-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware intra-procedural CWE-415 check
 * on AArch64. The scanner tracks the allocator's return register (`x0`) into a
 * stack slot (`str x0, [sp, #N]` / `[x29, #N]`), then watches for two
 * successive `bl <free>` calls whose first-argument register (`x0`) is
 * reloaded from (or copied off a reload of) that same slot — the double-free.
 *
 *   - double_free(): malloc -> free(p) -> free(p)   [VULN, high]  (no calls
 *                    between the two frees, keeping it intra-procedural)
 *   - safe_free():   malloc -> free(p)               [SAFE, silent] (single free)
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of malloc/free/_start in cwe415-aarch64-stubs.c. The host is
 * x86_64, so a full AArch64 libc/sysroot is not available; the freestanding
 * form lets a plain `clang --target=aarch64-linux-gnu` build a well-formed,
 * loadable AArch64 ELF whose `bl` targets resolve to the symbol names
 * malloc/free. autopsy resolves those names at the call sites and tracks the
 * pointer through the stack slot — exactly the signal the arch-aware
 * intra-procedural CWE-415 heuristic needs. See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the slot/register dataflow matter.
 *
 * Keep the two frees in double_free() with NO function call between them, so
 * the pattern stays intra-procedural (the v0.1 contract for this check).
 */
typedef unsigned long size_t;

void *malloc(size_t size);
void free(void *ptr);

/* Double-free: p is freed, then freed again with no intervening call. VULN. */
void double_free(void)
{
    char *p = malloc(32);
    free(p);          /* first free */
    free(p);          /* double-free: CWE-415 */
}

/* Single free of a freshly allocated pointer: must NOT be flagged. SAFE. */
void safe_free(void)
{
    char *q = malloc(16);
    free(q);          /* the only free -> no double-free */
}

int main(void)
{
    safe_free();
    double_free();
    return 0;
}
