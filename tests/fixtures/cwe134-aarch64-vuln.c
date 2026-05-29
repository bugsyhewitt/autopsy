/* CWE-134 (uncontrolled format string) fixture for AArch64 (ARM64).
 *
 * Mirrors cwe134-vuln.c but is built for the aarch64 architecture so the slow
 * test layer can exercise autopsy's arch-aware CWE-134 register-level check on
 * AArch64. The check reads the printf-family *format-string* argument out of
 * the AAPCS64 argument register (x0 for printf, x1 for fprintf) and confirms it
 * was reloaded from a stack slot (`ldr x0, [sp, #N]`) rather than materialized
 * as a constant `.rodata` pointer (`adrp`/`adr`).
 *
 *   - emit():     printf(user)            -> non-literal format   [VULN, medium]
 *   - emit_err(): fprintf(stderr, user)   -> non-literal format   [VULN, medium]
 *   - log_line(): printf("log: %s\n", u)  -> literal format       [SAFE, silent]
 *
 * A finding additionally requires an attacker-controlled input source in the
 * program (the same _SOURCES set as CWE-78); `main` reads a line via fgets(),
 * supplying that source. The literal-format printf in log_line() must NOT fire.
 *
 * It is FREESTANDING (no libc headers) and linked statically with stub
 * implementations of printf/fprintf/fgets/_start in cwe134-aarch64-stubs.c. The
 * host is x86_64, so a full AArch64 libc/sysroot is not available; the
 * freestanding form lets a plain `clang --target=aarch64-linux-gnu` build a
 * well-formed, loadable AArch64 ELF whose `bl` targets resolve to the symbol
 * names printf/fprintf/fgets. autopsy resolves those names at the call sites
 * and inspects the format-argument register — exactly the signal the arch-aware
 * CWE-134 heuristic needs. See REGENERATE.md for the build recipe.
 *
 * The stub bodies are irrelevant to detection; only the presence of the call
 * sites, their resolvable symbol names, and the format-register provenance
 * (stack-slot reload vs. adrp rodata pointer) matter.
 */
typedef unsigned long size_t;

int printf(const char *fmt, ...);
int fprintf(void *stream, const char *fmt, ...);
char *fgets(char *s, int size, void *stream);

void *stdin;
void *stderr;

/* VULNERABLE sink: the attacker-controlled buffer IS the format string. */
void emit(const char *user)
{
    printf(user);                /* CWE-134: x0 reloaded from a stack slot */
}

/* VULNERABLE sink: fprintf's format (x1) is the attacker buffer. */
void emit_err(const char *user)
{
    fprintf(stderr, user);       /* CWE-134: x1 reloaded from a stack slot */
}

/* SAFE: constant format string, user data passed as a %s argument. */
void log_line(const char *user)
{
    printf("log: %s\n", user);   /* literal format (adrp/adr) -> not a finding */
}

int main(void)
{
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) {
        return 0;
    }
    log_line(line);              /* safe use */
    emit(line);                  /* tainted input becomes the format string */
    emit_err(line);              /* tainted input becomes fprintf's format */
    return 0;
}
