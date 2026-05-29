/* CWE-416 (use-after-free, intra-procedural) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe416-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware intra-procedural CWE-416 check
 * on AArch64. The scanner tracks the allocator's return register (`x0`) into a
 * stack slot (`str x0, [sp, #N]` / `[x29, #N]`), confirms the freed pointer's
 * argument register (`x0`) aliases that slot at the `bl <free>` call, then —
 * with NO function call between the free and the use — watches for the same
 * pointer to be reloaded from the slot and dereferenced through that base
 * register (`str`/`ldr ..., [x9]`). That post-free dereference is the
 * use-after-free.
 *
 *   - use_after_free(): malloc -> free(p) -> p[0] = X   [VULN, high]  (no calls
 *                       between the free and the dereference, keeping it
 *                       intra-procedural)
 *   - safe_free():      malloc -> free(p)               [SAFE, silent] (the
 *                       freed pointer is never reused)
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of malloc/free/_start in cwe416-aarch64-stubs.c. The host is
 * x86_64, so a full AArch64 libc/sysroot is not available; the freestanding
 * form lets a plain `clang --target=aarch64-linux-gnu` build a well-formed,
 * loadable AArch64 ELF whose `bl` targets resolve to the symbol names
 * malloc/free. autopsy resolves those names at the call sites and tracks the
 * pointer through the stack slot — exactly the signal the arch-aware
 * intra-procedural CWE-416 heuristic needs. See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the slot/register dataflow matter.
 *
 * Keep the dereference in use_after_free() with NO function call between the
 * free and the use, so the pattern stays intra-procedural (the v0.1 contract
 * for this check). `volatile` keeps the dead store/load from being optimized
 * away even at -O0's neighbors.
 */
typedef unsigned long size_t;

void *malloc(size_t size);
void free(void *ptr);

/* Use-after-free: p is freed, then dereferenced with no intervening call. VULN. */
void use_after_free(void)
{
    volatile char *p = malloc(32);
    free((void *)p);        /* free path */
    p[0] = 'X';             /* use-after-free: write through the freed pointer */
}

/* Single free of a freshly allocated pointer, never reused: must NOT fire. SAFE. */
void safe_free(void)
{
    char *q = malloc(16);
    free(q);                /* the freed pointer is never dereferenced again */
}

int main(void)
{
    safe_free();
    use_after_free();
    return 0;
}
