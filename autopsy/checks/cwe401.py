"""CWE-401: Missing Release of Memory after Effective Lifetime (memory leak).

Strategy (whole-program, register-level, intra-procedural): flag every
*owned-allocator* call (``malloc``/``calloc``/``realloc``/``reallocarray``/
``strdup``/``strndup``) whose result the function provably never releases and
never lets escape its scope. A leak is reported only when *all four* common
ownership-transfer paths are absent before the function returns:

  * No ``free``/``realloc``/``reallocarray`` call whose first argument aliases
    the slot (the slot is never released here).
  * No reload of the slot into the architecture's return register
    (``rax`` on x86_64, ``x0`` on AArch64) before a ``ret`` (the pointer is
    not returned to the caller).
  * No reload of the slot into any integer argument register before any
    non-release call (the pointer is not handed to a callee that might take
    ownership, store it, or free it).
  * No store of an aliasing register to a memory location other than the
    original spill slot (the pointer is not stashed somewhere persistent like
    a struct field, a global, or another stack frame).

If any of those four escapes appears, the function is treated as transferring
ownership and the site stays silent. This narrow conservative pattern is what
preserves autopsy's zero-false-positive posture: the canonical
``p = malloc(64); use(p); free(p);`` is silent (a release call clears the
finding), and the canonical ``char *make(void){ return malloc(64); }`` is
silent (a return-register escape clears the finding).

CWE-401 is a perennial Top-50 weakness class — long-running services
accumulate leaks into OOMs, denials of service, and (when an
attacker-influenced path leaks) exploitable resource exhaustion. Detecting it
purely from a stripped binary is hard because ownership semantics live in the
programmer's head, not in the ELF; this check tracks the slot through the
function but cannot follow ownership across calls, so it is deliberately
intra-procedural — every escape suppresses the finding, which is the right
trade for autopsy's "tight signal" posture.

``getenv`` and ``secure_getenv`` are deliberately *excluded* from the owned
allocator set: their return values point at process-environment storage
owned by libc and must **not** be freed by the caller, so an unfreed
``getenv()`` result is not a leak. (CWE-476 still tracks ``getenv()`` results
for unchecked dereferences — that is a different weakness.)

Arch-aware (x86_64 + AArch64). The engine helper carries two parallel walkers
that share the same algorithm — spill the allocator's return register into a
stack slot, follow alias propagation through slot reloads and register copies,
treat any free/return/arg-pass/memory-store as an escape, and report only when
the function exits with the slot still owned. On any other architecture the
engine returns an empty list and this check stays silent.

Findings carry ``confidence: "medium"``: an owned allocator with no observed
release or escape is a strong structural signal of a leak, but the
intra-procedural slot tracking is not a full ownership proof — an alias path
the scanner misses (e.g. through a struct field write the regex profile
does not recognize) could legitimately transfer ownership without being
visible. The medium level matches the existing CWE-787/125/134 disclosure
(``call_site + structural signal + program-wide input source not symbolically
proven``).
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def run(engine) -> list[Finding]:
    sites = engine.unfreed_allocations()
    if not sites:
        return []

    findings: list[Finding] = []
    for site in sites:
        alloc = site["alloc_name"]
        evidence = (
            f"{alloc}() in {site['function']} returns an owned heap pointer "
            f"that is never freed and never escapes the function (no "
            f"free()/realloc(), no return, no argument-pass, no memory store) "
            f"— the allocation leaks when the function exits"
        )
        trace = [
            TaintPoint(
                site["alloc_address"],
                f"heap allocation via {alloc}() — caller owns the returned pointer",
            ),
            TaintPoint(
                site["address"],
                f"the allocator result is spilled to stack slot {site['slot']} "
                f"and never released or transferred before the function returns",
            ),
        ]
        findings.append(
            Finding(
                cwe=401,
                function=site["function"],
                address=site["address"],
                evidence=evidence,
                taint_trace=trace,
                # An owned allocator with no observed release or escape is a
                # strong structural leak signal, but the intra-procedural slot
                # tracking is not a full ownership proof -> medium.
                confidence="medium",
            )
        )
    return findings
