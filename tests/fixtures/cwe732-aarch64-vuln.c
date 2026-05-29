/* CWE-732 (incorrect permission assignment) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe732-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-732 register-level check on
 * AArch64. The check reads the chmod/umask *mode* immediate out of the AAPCS64
 * argument register (x1/w1 for chmod, x0/w0 for umask) materialized by a `mov`
 * into the w-view just before the `bl` (branch-with-link) call.
 *
 *   - expose_secret(): chmod(path, 0777) -> group+world write   [VULN, high]
 *   - widen_shared():  chmod(path, 0666) -> group+world write   [VULN, high]
 *   - loose_umask():   umask(0)          -> masks nothing       [VULN, medium]
 *   - lock_down():     chmod(path, 0600) -> owner-only          [SAFE, silent]
 *   - tight_umask():   umask(0077)       -> strips group/other  [SAFE, silent]
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of chmod/umask/_start in cwe732-aarch64-stubs.c. The host is
 * x86_64, so a full AArch64 libc/sysroot is not available; the freestanding
 * form lets a plain `clang --target=aarch64-linux-gnu` build a well-formed,
 * loadable AArch64 ELF whose `bl` targets resolve to the symbol names chmod and
 * umask. autopsy resolves those names at the call sites and reads the immediate
 * mode/mask from the argument register — exactly the signal the arch-aware
 * CWE-732 heuristic needs. See REGENERATE.md for the build recipe.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the mode/mask immediates matter.
 */
typedef unsigned int mode_t;

int chmod(const char *path, mode_t mode);
int umask(mode_t mask);

/* World-writable: 0777 sets the world-write bit (0o002). VULNERABLE. */
int expose_secret(const char *path)
{
    return chmod(path, 0777);
}

/* Group+world readable/writable: 0666 sets group-write and world-write. VULNERABLE. */
int widen_shared(const char *path)
{
    return chmod(path, 0666);
}

/* umask(0) masks nothing -> new files keep group/world write. VULNERABLE. */
void loose_umask(void)
{
    umask(0);
}

/* Owner read/write only: restrictive, must NOT be flagged. SAFE. */
int lock_down(const char *path)
{
    return chmod(path, 0600);
}

/* Strips all group/other permission bits: restrictive, must NOT fire. SAFE. */
void tight_umask(void)
{
    umask(0077);
}

int main(void)
{
    const char *path = "/tmp/data";
    tight_umask();
    loose_umask();
    lock_down(path);
    expose_secret(path);
    widen_shared(path);
    return 0;
}
