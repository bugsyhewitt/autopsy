/*
 * CWE-362 fixture: Concurrent execution using shared resource with improper
 * synchronization — specifically, async-signal-unsafe libc calls inside an
 * installed signal handler.
 *
 *   - unsafe_handler() is installed via signal(SIGUSR1, ...) and calls
 *     printf() and malloc(): both are explicitly NOT on the POSIX.1-2017
 *     §2.4.3 async-signal-safe list. A signal delivered mid-printf or
 *     mid-malloc races against the same global state (FILE-lock recursion /
 *     heap-arena reentrancy). autopsy must flag each of those unsafe calls.
 *
 *   - safe_handler() is installed via signal(SIGUSR2, ...) and calls ONLY
 *     write() and _exit() — both async-signal-safe per POSIX. autopsy must
 *     NOT flag any call inside safe_handler() (zero false positives).
 *
 *   - unused_unsafe_helper() also calls printf()/malloc() but is never
 *     installed as a handler — autopsy must NOT flag it (the weakness is
 *     installation-as-handler, not the call itself, which is CWE-676's job).
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

/* VULNERABLE handler: calls printf (buffered stdio) and malloc (heap arena)
 * — both async-signal-UNSAFE. A signal delivered while the main flow is
 * inside printf/malloc will reenter the same code path on the same thread
 * and corrupt the shared state. */
void unsafe_handler(int sig) {
    printf("got signal %d\n", sig);   /* CWE-362: stdio in handler */
    char *p = malloc(64);             /* CWE-362: malloc in handler */
    if (p) {
        free(p);                      /* CWE-362: free in handler */
    }
}

/* SAFE handler: write() and _exit() are explicitly on the POSIX async-signal-
 * safe list. autopsy must NOT flag this handler. */
void safe_handler(int sig) {
    const char msg[] = "exiting\n";
    write(2, msg, sizeof(msg) - 1);   /* write() is async-signal-safe */
    _exit(0);                         /* _exit() is async-signal-safe */
}

/* Calls printf/malloc but is never installed as a handler. The CWE-362
 * weakness is the *handler-installation*; if this function is not registered
 * via signal()/sigaction(), there is no race. autopsy must NOT flag it under
 * CWE-362 (CWE-676 handles dangerous functions in general, separately). */
void unused_unsafe_helper(void) {
    printf("just a regular helper\n");
    char *p = malloc(16);
    if (p) free(p);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    signal(SIGUSR1, unsafe_handler);  /* installs the racy handler */
    signal(SIGUSR2, safe_handler);    /* installs the async-signal-safe handler */
    unused_unsafe_helper();           /* call it so it isn't dead-stripped */
    return 0;
}
