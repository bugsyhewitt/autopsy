"""CWE-362: Concurrent Execution using Shared Resource — async-signal-unsafe
call inside a signal handler.

Strategy (whole-program, register-level just enough to resolve a single
function-pointer argument): flag every call inside an installed signal handler
to a libc function that is NOT on the POSIX.1-2017 §2.4.3 async-signal-safe
list. A signal can land at any instruction boundary on the same thread,
including in the middle of a libc call already in progress. If the handler
then invokes the *same* family — ``printf`` while the main flow was inside
``printf`` (FILE-lock recursion / stdio-buffer corruption), ``malloc`` while
the main flow was inside ``malloc`` (heap-arena reentrancy / deadlock) — the
shared global state races with itself. This is the canonical
"improper-synchronization-of-a-shared-resource" race weakness MITRE classes
under CWE-362, distinct from the CWE-367 TOCTOU file-system race the suite
already detects.

The detector is purely call-site-driven, plus one narrow form of pointer
resolution: walk back from each ``signal(sig, handler)`` call to read the
*absolute address* loaded into the second argument register (SysV ``rsi`` on
x86_64, AAPCS64 ``x1`` on AArch64), then resolve that address to a function
via the CFG. The engine helper recognizes the x86_64 ``lea rsi, [rip + disp]``
RIP-relative form (the canonical -O0 emission for a function-address literal)
and the AArch64 ``adrp x1, page ; add x1, x1, #:lo12:sym`` page+offset form.
Handlers passed by *indirection* — loaded from a struct field, returned by an
earlier call — are intentionally unresolvable and stay silent, preserving the
zero-false-positive posture.

Signal-installer aliases handled: ``signal``, ``__sysv_signal``, ``bsd_signal``,
``sysv_signal``, ``sigset``. ``sigaction`` is deliberately NOT handled in this
release — its handler lives inside a ``struct sigaction`` referenced by
pointer, which would require struct-field reasoning beyond the
single-immediate-arg resolution this check stays in scope for. That gap is
documented in the post-v0.1 directions; an installed-handler set imported via
``sigaction`` would currently miss findings rather than emit false positives,
which is the conservative-safe failure mode.

Async-signal-unsafe set: the POSIX list is by enumeration of what IS safe
(``_exit``, ``write``, ``read``, ``signal``, ``raise``, ``kill``, ``sigaction``
and a small set of pure helpers), so the unsafe list is everything else; this
detector targets the high-signal categories — buffered stdio
(``printf``/``fprintf``/``puts``/``fputs``/``fopen``/``fclose``/``fread``/
``fwrite``/``fflush``/``fgets``), locale-sensitive formatters/scanners
(``sprintf``/``snprintf``/``sscanf``/``scanf``/``__isoc99_*``/``localtime``/
``ctime``/``asctime``/``gmtime`` non-reentrant variants), dynamic allocators
(``malloc``/``calloc``/``realloc``/``reallocarray``/``free``/``strdup``/
``strndup``), ``syslog``, and ``exit`` (which runs ``atexit`` hooks and flushes
stdio — the safe forms are ``_Exit``/``_exit``). The bounded scanf/printf
siblings and the descriptor-level I/O (``write``/``read``) are intentionally
absent.

Like CWE-676/367/377, CWE-362 needs no attacker-input source: the weakness is
the call itself — every signal delivery is the asynchronous "input" that
materializes the race. Findings carry ``confidence: "high"``: the
handler-pointer→function resolution is exact (an absolute literal address
landing in a known function), and the unsafe-call enumeration is exact
(direct call to a named libc symbol on the POSIX-unsafe list). There is no
register-level heuristic; the only soundness gap is unresolvable
indirect-installed handlers, which stay silent rather than false-positive.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def run(engine) -> list[Finding]:
    sites = engine.signal_handler_unsafe_calls()
    if not sites:
        return []

    findings: list[Finding] = []
    for site in sites:
        handler = site["handler"]
        installer = site["installer"]
        unsafe = site["unsafe_name"]
        evidence = (
            f"{installer}() installs {handler}() as a signal handler, and "
            f"{handler}() calls async-signal-unsafe {unsafe}(); a signal "
            f"delivered while the program is mid-{unsafe}() will reenter "
            f"{unsafe}() inside the handler, racing the shared global state "
            f"(POSIX.1-2017 §2.4.3 lists {unsafe}() as not async-signal-safe) "
            f"— use only async-signal-safe primitives in the handler "
            f"(e.g. write() instead of printf(), _Exit() instead of exit()), "
            f"or set a sig_atomic_t flag and handle the work outside the "
            f"handler"
        )
        findings.append(
            Finding(
                cwe=362,
                # The damage lands inside the handler, so anchor there.
                function=handler,
                address=site["unsafe_address"],
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        site["install_address"],
                        f"signal-installation: {installer}() registers "
                        f"{handler}() as the handler — the handler can run "
                        f"asynchronously on the same thread",
                    ),
                    TaintPoint(
                        site["unsafe_address"],
                        f"async-signal-unsafe use: {handler}() calls "
                        f"{unsafe}(), which shares global state (FILE locks / "
                        f"heap arena / locale buffers) with the interrupted "
                        f"flow",
                    ),
                ],
                # Both halves are resolved exactly (handler-pointer → known
                # function, unsafe call → direct named libc call). No
                # register-level heuristic is involved; the only soundness gap
                # is unresolvable indirect handlers (which stay silent), so
                # when this check fires the finding is high confidence.
                confidence="high",
            )
        )
    return findings
