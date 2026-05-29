/* CWE-476 (NULL pointer dereference) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe476-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-476 check on AArch64.
 *
 * Detection model on AArch64 (same shape as x86_64):
 *
 *   - The allocator's return register is ``x0`` (AAPCS64). -O0 codegen spills
 *     it to a stack slot via ``str x0, [sp, #N]`` (or ``[x29, #N]``) right
 *     after the call.
 *
 *   - A later use reloads the slot into a register (``ldr xR, [sp, #N]``) and
 *     dereferences it (``str``/``ldr ..., [xR]``). The engine helper
 *     ``unchecked_alloc_dereferences`` walks alias propagation through slot
 *     reloads and register-to-register copies.
 *
 *   - A NULL-check guard is either ``cbz``/``cbnz`` on a slot-aliased register,
 *     or a ``cmp xR, #0`` / ``cmp xR, xzr`` / ``tst xR, xR`` followed by a
 *     ``b.<cond>`` branch. If a guard appears between the spill and the
 *     dereference, the site is silent (zero-false-positive posture).
 *
 *   - ``risky_fill()``: ``int *p = malloc(...); p[0] = 42;`` with NO NULL-check
 *     — the AArch64 codegen reloads ``x0`` from the slot and stores through
 *     it (``str wzr, [x0]``-style) with no preceding ``cbz``. CWE-476 fires
 *     [VULN, medium].
 *
 *   - ``safe_fill()``: ``if (!p) return -1;`` guards the result via ``cbz``
 *     (or ``cmp x0, #0`` + ``b.eq``). The check must NOT fire [SAFE, silent].
 *
 *   - ``safe_env()``: ``char *home = getenv("HOME"); if (!home) return 0;``
 *     The getenv() result is NULL-checked before strlen() reads it. The check
 *     must NOT fire [SAFE, silent].
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of malloc/getenv/strlen/atoi/fgets/_start in
 * cwe476-aarch64-stubs.c. The host is x86_64, so a full AArch64 libc/sysroot
 * is not available; the freestanding form lets a plain
 * ``clang --target=aarch64-linux-gnu`` build a well-formed, loadable AArch64
 * ELF whose ``bl`` targets resolve to the symbol names malloc/getenv/strlen.
 * See REGENERATE.md.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the spill/reload/guard pattern
 * matter.
 */
typedef unsigned long size_t;

void *malloc(size_t size);
char *getenv(const char *name);
size_t strlen(const char *s);
char *fgets(char *s, int size, void *stream);
int atoi(const char *nptr);

/* Vulnerable: malloc result is dereferenced with NO NULL-check. The codegen
 * spills x0 into a stack slot after the bl malloc, reloads it, and stores
 * through it without an intervening cbz/cmp+b.eq guard. */
int risky_fill(int n)
{
    int *p = (int *)malloc((size_t)n * sizeof(int));
    p[0] = 42;                 /* SIGSEGV if malloc returned NULL */
    return p[0];
}

/* Safe: the malloc result is NULL-checked before use. The codegen emits a
 * ``cbz x0, .L_ret`` (or ``cmp x0, #0; b.eq .L_ret``) on the reloaded slot —
 * the engine's AArch64 guard recognizer must catch this and stay silent. */
int safe_fill(int n)
{
    int *p = (int *)malloc((size_t)n * sizeof(int));
    if (p == (void *)0) {       /* NULL-check guard */
        return -1;
    }
    p[0] = 42;
    return p[0];
}

/* Safe: getenv() result is NULL-checked before strlen() reads through it. */
size_t safe_env(void)
{
    char *home = getenv("HOME");
    if (!home) {                /* NULL-check guard */
        return 0;
    }
    return strlen(home);
}

int main(void)
{
    char line[64];
    int n;
    size_t r;

    if (!fgets(line, sizeof(line), (void *)0)) return 0;
    n = atoi(line);
    (void)risky_fill(n);
    (void)safe_fill(n);
    r = safe_env();
    (void)r;
    return 0;
}
