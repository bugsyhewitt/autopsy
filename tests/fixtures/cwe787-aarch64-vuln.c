/* CWE-787 (heap out-of-bounds write) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe787-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-787 check on AArch64.
 *
 * Detection model on AArch64 (same shape as x86_64):
 *
 *   - The check enumerates allocator/source/copy call sites by *symbol name*
 *     (call-site discovery is already arch-agnostic), then suppresses copies
 *     whose *length* argument is a compile-time immediate via the engine
 *     helper ``copy_call_length_is_literal``. The length-argument register on
 *     AAPCS64 is ``x2`` (32-bit view ``w2``); a literal length is materialized
 *     into the ``w2`` view (zero-extending into ``x2``) and a runtime
 *     (possibly tainted) length reloads from a stack slot.
 *
 *   - ``copy_to_heap()``: malloc(size) + memcpy(dst, src, length) where size
 *     and length are independent tainted values — the *length* argument is
 *     reloaded from a stack slot (`ldr w2, [sp, #N]`), so the call is NOT
 *     suppressed and CWE-787 fires.  [VULN, medium]
 *
 *   - ``safe_copy()``: malloc(64) + strncpy(p, line, 63) where the length is
 *     a compile-time immediate (`mov w2, #0x3f`), so the suppression helper
 *     classes it as literal and CWE-787 must NOT fire.  [SAFE, silent]
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of malloc/free/fgets/atoi/memcpy/strncpy/_start in
 * cwe787-aarch64-stubs.c. The host is x86_64, so a full AArch64 libc/sysroot
 * is not available; the freestanding form lets a plain
 * `clang --target=aarch64-linux-gnu` build a well-formed, loadable AArch64
 * ELF whose `bl` targets resolve to the symbol names malloc/memcpy/strncpy/
 * fgets/atoi — exactly the signal the arch-aware CWE-787 heuristic needs.
 * See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the length-arg immediate vs
 * stack-reload pattern matter.
 */
typedef unsigned long size_t;

void *malloc(size_t size);
void free(void *ptr);
void *memcpy(void *dst, const void *src, size_t n);
char *strncpy(char *dst, const char *src, size_t n);
char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);

/* Vulnerable: heap buffer allocated with a tainted size; memcpy writes into it
 * with an *independently* tainted length. Both size and length reload from
 * stack slots (the AAPCS64 length register w2 is loaded via `ldr w2, [sp,
 * #N]`), so the literal-length suppression does NOT fire and CWE-787 reports.
 */
void copy_to_heap(int size, int length)
{
    char *buf = malloc((size_t)size);     /* allocation size is tainted */
    if (!buf) return;
    static char src[256];                 /* static zero-initialized; no memset */
    memcpy(buf, src, (size_t)length);     /* length tainted -> w2 reloaded */
    free(buf);
}

/* Safe: the copy length is a compile-time literal (63), so even with an
 * attacker-input source present in the program the literal-length suppression
 * fires and CWE-787 must NOT report this function. -O0 materializes the 63 as
 * `mov w2, #0x3f` immediately before the `bl strncpy`. */
void safe_copy(const char *line)
{
    char *p = malloc(64);
    if (!p) return;
    strncpy(p, line, 63);                 /* literal length -> suppressed */
    free(p);
}

int main(void)
{
    char line[64];
    int alloc_size, copy_len;

    /* attacker-input sources: fgets + atoi (in the same _SOURCES set the
     * check requires for taint). Without these the check returns no findings
     * for any function, regardless of the malloc+copy co-location. */
    if (!fgets(line, sizeof(line), (void *)0)) return 0;
    alloc_size = atoi(line);

    if (!fgets(line, sizeof(line), (void *)0)) return 0;
    copy_len = atoi(line);

    safe_copy(line);                      /* literal-length copy: not flagged */
    copy_to_heap(alloc_size, copy_len);   /* tainted-length copy: flagged */
    return 0;
}
