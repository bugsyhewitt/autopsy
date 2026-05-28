"""CWE-415: double-free, single-hop INTERPROCEDURAL.

The intra-procedural :mod:`autopsy.checks.cwe415` check catches the case where
both ``free()`` calls live in one function body. Real-world double-free bugs,
however, frequently span a call boundary: a pointer is freed in one function
and then handed to a helper that frees it again. This module detects the most
common, most tractable, cross-function shape — the *single-hop* pattern:

    void release(thing *p) { free(p); }     // callee frees its argument

    void run(void) {
        thing *t = make();
        free(t);        // FIRST free, in the caller
        release(t);     // pointer handed to a callee that frees it AGAIN
    }

This is distinct from the interprocedural use-after-free check
(:mod:`autopsy.checks.cwe416_interproc`): there the bug is a *dereference* of
the freed pointer after the callee frees it. Here the bug is the *second free
call itself* — the pointer was already freed by the caller before being passed
to the freeing callee.

Detection (call-graph driven + caller-side slot tracking):

  1. From the engine, find every in-binary function ``F`` that calls ``free``
     on its *incoming parameter* (``engine.in_binary_callees_freeing_arg``).
     These are the helpers that free a caller-supplied pointer.
  2. For each such ``F``, find its in-binary callers ``G``
     (``engine.callers_of``).
  3. For each call site ``G -> F``, ask the engine whether ``G`` already freed
     the pointer it passes to ``F``, earlier in ``G``'s body, with no
     intervening reallocation of that pointer
     (``engine.caller_frees_arg_before_call``). If so, ``F`` will free an
     already-freed pointer — a single-hop cross-function double-free.

Scope (deliberately bounded — mirrors the cwe416_interproc caveat):
  * Exactly one call hop (caller -> freeing callee). Deeper chains are not
    followed, preserving the zero-false-positive guarantee on the clean
    baseline.
  * A reallocation of the slot between the first free and the handoff cancels
    the candidate (the second free would then be a legitimate first free of
    fresh memory).

Confidence is ``"medium"``: the first free (in the caller) and the second free
(in the callee) are both confirmed via stack-slot aliasing, but the single-hop,
parameter-based handoff is a structural match rather than a full data-flow
proof. The intra-procedural double-free (both frees in one body, alias-confirmed
with no intervening reallocation) remains ``"high"``.

x86_64 only: the alias tracking relies on the SysV first-argument register
(``rdi``) and -O0 stack-slot spill conventions, consistent with the
register-level checks the engine already restricts to x86_64.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def run(engine) -> list[Finding]:
    """Detect single-hop cross-function double-free findings.

    Returns one finding per (caller, freeing-callee) call site where the caller
    already freed the pointer it passes to the callee.
    """
    freeing = _freeing_callees(engine)
    if not freeing:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for callee_name in freeing:
        for call in _callers_of(engine, callee_name):
            # A function calling itself is not a single-hop interprocedural
            # case; the intra-procedural pass handles same-function frees.
            if call.caller_function == callee_name:
                continue
            key = (call.caller_function, call.call_address)
            if key in seen:
                continue
            first_free_addr = _caller_first_free(
                engine, call.caller_function, call.call_address
            )
            if first_free_addr is None:
                continue
            seen.add(key)
            findings.append(
                _build_finding(
                    caller=call.caller_function,
                    callee=callee_name,
                    first_free_addr=first_free_addr,
                    second_free_call_addr=call.call_address,
                )
            )
    return findings


# -- engine adapters (kept tiny so the run() logic is unit-testable) ---------


def _freeing_callees(engine) -> set[str]:
    fn = getattr(engine, "in_binary_callees_freeing_arg", None)
    return fn() if callable(fn) else set()


def _callers_of(engine, name: str):
    fn = getattr(engine, "callers_of", None)
    return fn(name) if callable(fn) else []


def _caller_first_free(engine, caller_name: str, call_addr: int) -> int | None:
    fn = getattr(engine, "caller_frees_arg_before_call", None)
    return fn(caller_name, call_addr) if callable(fn) else None


def _build_finding(
    caller: str, callee: str, first_free_addr: int, second_free_call_addr: int
) -> Finding:
    trace = [
        TaintPoint(first_free_addr, f"pointer freed in {caller} via free()"),
        TaintPoint(
            second_free_call_addr,
            f"already-freed pointer passed to {callee}(), which frees it again "
            f"(double-free)",
        ),
    ]
    return Finding(
        cwe=415,
        function=caller,
        address=second_free_call_addr,
        evidence=(
            f"single-hop cross-function double-free: {caller} frees a pointer at "
            f"{hex(first_free_addr)} then passes it to {callee}() (which frees it "
            f"again) at {hex(second_free_call_addr)} with no intervening "
            f"reallocation"
        ),
        taint_trace=trace,
        confidence="medium",
    )
