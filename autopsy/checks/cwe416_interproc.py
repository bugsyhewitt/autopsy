"""CWE-416: use-after-free, single-hop INTERPROCEDURAL.

The intra-procedural :mod:`autopsy.checks.cwe416` check catches free-then-use
within one function body. Real-world UAF bugs, however, are almost always
cross-function: the freeing code and the dangling dereference live in different
functions (see POST_V01 Tier 2 #4). This module detects the most common, and
most tractable, cross-function shape — the *single-hop* pattern:

    void release(thing *p) { ...; free(p); }   // callee frees its argument

    void use(void) {
        thing *t = make();
        release(t);     // pointer handed to a callee that frees it
        t->field = ...; // caller dereferences the now-dangling pointer
    }

Detection (call-graph driven + caller-side slot tracking):

  1. From the engine, find every in-binary function ``F`` that calls ``free``
     on its *incoming parameter* (``engine.in_binary_callees_freeing_arg``).
     These are the helpers that can leave a caller-held pointer dangling.
  2. For each such ``F``, find its in-binary callers ``G``
     (``engine.callers_of``).
  3. For each call site ``G -> F``, ask the engine whether ``G`` dereferences
     the pointer it passed to ``F`` *after* the call returns, with no
     intervening call (``engine.caller_uses_arg_after_call``). If so, the
     caller-held pointer is used after the callee freed it — a single-hop
     cross-function use-after-free.

Scope (deliberately bounded — see the POST_V01 feasibility caveat):
  * Exactly one call hop (caller -> freeing callee). Deeper chains are not
    followed; that risks the false positives and path-explosion the caveat
    warns about.
  * The dereference must occur before any other call in the caller, keeping
    the alias reasoning sound (a subsequent call could re-validate or
    reassign the pointer).

Confidence is ``"medium"``: the free-in-callee and use-in-caller are both
confirmed via stack-slot aliasing, but the single-hop, no-intervening-call
restriction means this is a structural match rather than a full data-flow
proof.

x86_64 only: the alias tracking relies on the SysV first-argument register
(``rdi``) and -O0 stack-slot spill conventions, consistent with the
register-level checks (CWE-119/415/416/787) that the engine already restricts
to x86_64.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def run(engine) -> list[Finding]:
    """Detect single-hop cross-function use-after-free findings.

    Returns one finding per (caller, freeing-callee) call site where the caller
    dereferences the passed-in pointer after the callee frees it.
    """
    freeing = _freeing_callees(engine)
    if not freeing:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for callee_name in freeing:
        for call in _callers_of(engine, callee_name):
            # Don't double-report the intra-procedural case (a function calling
            # itself recursively would be handled by the intra pass).
            if call.caller_function == callee_name:
                continue
            key = (call.caller_function, call.call_address)
            if key in seen:
                continue
            use_addr = _caller_use(engine, call.caller_function, call.call_address)
            if use_addr is None:
                continue
            seen.add(key)
            findings.append(
                _build_finding(
                    caller=call.caller_function,
                    callee=callee_name,
                    call_addr=call.call_address,
                    use_addr=use_addr,
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


def _caller_use(engine, caller_name: str, call_addr: int) -> int | None:
    fn = getattr(engine, "caller_uses_arg_after_call", None)
    return fn(caller_name, call_addr) if callable(fn) else None


def _build_finding(caller: str, callee: str, call_addr: int, use_addr: int) -> Finding:
    trace = [
        TaintPoint(call_addr, f"pointer passed to {callee}(), which frees it"),
        TaintPoint(
            use_addr,
            f"freed pointer dereferenced in {caller} after {callee}() returned "
            f"(use-after-free)",
        ),
    ]
    return Finding(
        cwe=416,
        function=caller,
        address=use_addr,
        evidence=(
            f"single-hop cross-function use-after-free: {caller} passes a pointer "
            f"to {callee}() (which frees it) then dereferences it at "
            f"{hex(use_addr)} with no intervening call"
        ),
        taint_trace=trace,
        confidence="medium",
    )
