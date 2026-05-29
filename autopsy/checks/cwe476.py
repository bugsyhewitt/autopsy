"""CWE-476: NULL Pointer Dereference.

Strategy (whole-program, register-level): flag every NULL-returning allocator
result that is dereferenced before the program tests it against NULL. The
canonical pattern is ``p = malloc(n); p[0] = ...;`` (or any read/write through
``p``) with no intervening ``if (p == NULL)`` check: when the allocation fails
``malloc`` returns NULL, the dereference faults on the unmapped zero page
(SIGSEGV), and on some targets an attacker who can force the failure escalates
the crash into a controlled write. CWE-476 is one of the most frequently
reported weakness classes in C/C++ and a perennial CWE Top 25 entry.

The allocators tracked are the ones whose contract is "returns NULL on
failure / absence" — ``malloc``/``calloc``/``realloc``/``reallocarray``,
``strdup``/``strndup`` (OOM), and ``getenv``/``secure_getenv`` (variable not
set). The engine helper :meth:`AngrEngine.unchecked_alloc_dereferences` does
the disassembly-level work: it finds each allocator call, locates the stack
slot the result (``rax`` on x86_64 SysV) was spilled into, and scans forward
for the first dereference through a register reloaded from that slot — unless a
NULL-check guard (a ``test``/``cmp`` on the result, followed by a conditional
branch) intervenes first.

Excluding guarded sites is what preserves autopsy's zero-false-positive
posture: ``p = malloc(n); if (!p) return; p[0] = ...;`` checks before it uses
and must stay silent. Like CWE-732/676/377, CWE-476 needs no attacker-input
source — the missing NULL-check is the weakness itself, which is how MITRE
frames it. The finding is reported at ``medium`` confidence: an unchecked
dereference of an allocator result is a strong structural signal, but the
register-level slot tracking does not constitute a full def-use proof that the
specific faulting access is the same pointer on every path.

Arch-aware (x86_64 + AArch64). The engine helper carries two parallel walkers
that share the same algorithm — spill the allocator's return register into a
stack slot, follow alias propagation through slot reloads and register copies,
report the first dereference through an aliasing register unless a NULL-check
guard intervenes. The x86_64 (SysV) walker uses ``rax``, ``mov [rbp-N], rax``
spills, and ``test``/``cmp`` + conditional-jump guards. The AArch64 (AAPCS64)
walker uses ``x0``, ``str x0, [sp,#N]``/``[x29,#N]`` spills, and the AArch64
guard idioms (``cbz``/``cbnz`` on a slot-aliased register, or
``cmp xR, #0``/``cmp xR, xzr``/``tst xR, xR`` followed by ``b.<cond>``). On any
other architecture the engine returns an empty list and this check stays silent.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def run(engine) -> list[Finding]:
    sites = engine.unchecked_alloc_dereferences()
    if not sites:
        return []

    findings: list[Finding] = []
    for site in sites:
        alloc = site["alloc_name"]
        evidence = (
            f"pointer returned by {alloc}() in {site['function']} is "
            f"dereferenced with no NULL-check; a failed/absent {alloc}() "
            f"returns NULL and the dereference faults (SIGSEGV)"
        )
        trace = [
            TaintPoint(
                site["alloc_address"],
                f"{alloc}() may return NULL (allocation failure / absent value)",
            ),
            TaintPoint(
                site["address"],
                f"dereference of the {alloc}() result with no intervening "
                f"NULL-check",
            ),
        ]
        findings.append(
            Finding(
                cwe=476,
                function=site["function"],
                address=site["address"],
                evidence=evidence,
                taint_trace=trace,
                # Unchecked deref of an allocator result is a strong structural
                # signal, but the slot tracking is not a full def-use proof of
                # the faulting pointer on every path -> medium.
                confidence="medium",
            )
        )
    return findings
