"""CWE-787: Out-of-Bounds Write — heap buffer overflow via malloc+memcpy taint mismatch.

Strategy (whole-program): detect the classic pattern where a heap buffer is
allocated with malloc/calloc (size = N) and then a bulk-copy function
(memcpy/memmove/strcpy/memset) writes into it using a *different* length
argument (M).  When both N and M are derived from attacker-controlled input
(via the same taint sources tracked by CWE-190) the write length M may exceed
the allocation size N — an out-of-bounds heap write.

Detection steps:
  1. Find calls to malloc/calloc/realloc.
  2. For each allocator call, check whether the function also contains a call
     to a bulk-copy/fill function (memcpy, memmove, strcpy, memset) in the
     same function.
  3. Require at least one *eligible* copy sink in that function — one whose
     length argument is NOT a compile-time literal.  A copy with a literal
     (immediate) length (e.g. ``strncpy(p, line, 63)`` against ``malloc(64)``)
     has a fixed, attacker-independent write extent and cannot produce a
     tainted out-of-bounds write, so it is excluded.  ``strcpy`` has no length
     argument and is always eligible.
  4. Confirm that the program has at least one attacker-controlled input
     source in scope (same ``_SOURCES`` set as CWE-190).
  5. Flag with severity HIGH, confidence "medium" — the two-argument
     mismatch heuristic catches the structural pattern but cannot prove at
     this level of analysis that M > N on all paths.

Confidence rationale:
  "medium" — we confirm the co-location of allocator + copy sink (with a
  non-literal length) in one function AND the presence of an input source, but
  we do not symbolically evaluate whether M > N.  That would require full
  heap-size tracking which is a post-v0.1 direction.

[Worker decision: function-scope co-location heuristic] Full def-use chain
tracking from malloc return value to copy destination is complex and fragile
in angr CFGFast mode.  The co-location heuristic (allocator + copy in same
function + input source in program) matches the real-world pattern
``malloc(n); memcpy(dst, src, m)`` where n and m are independent tainted
values and is sufficient for a "medium" confidence finding.

[Worker decision: literal-length suppression (R9)] The original co-location
heuristic fired on the clean-baseline binary, which contains the entirely safe
``malloc(64); strncpy(p, line, 63)`` pattern — a false positive, because the
copy length (63) is a compile-time constant and cannot be tainted.  The check
now asks the engine whether each copy sink's length argument is a literal
immediate (``engine.copy_call_length_is_literal``); a function is only flagged
if it has at least one copy sink whose length is *not* provably literal.  This
restores the zero-false-positive guarantee on the clean baseline while still
catching the genuinely-vulnerable variable-length copy pattern.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

_ALLOCATORS = {"malloc", "calloc", "realloc", "reallocarray"}
_COPY_SINKS = {"memcpy", "memmove", "strcpy", "strncpy", "memset", "bcopy"}
_SOURCES = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}


def run(engine) -> list[Finding]:
    """Detect malloc+copy co-location with a global taint source.

    Returns one finding per function that contains both an allocator call
    and a bulk-copy/fill call, provided the program has at least one
    attacker-controlled input source.
    """
    alloc_calls = engine.call_sites_to(_ALLOCATORS)
    if not alloc_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []
    copy_calls = engine.call_sites_to(_COPY_SINKS)
    if not copy_calls:
        return []

    # Group allocator calls and copy calls by containing function.
    alloc_by_func: dict[str, list] = {}
    for cs in alloc_calls:
        alloc_by_func.setdefault(cs.caller_function, []).append(cs)

    # Only copy sinks whose length argument is NOT a provable compile-time
    # literal are eligible: a literal-length copy (e.g. strncpy(p, line, 63))
    # has a fixed, attacker-independent write extent and cannot cause a tainted
    # out-of-bounds write. ``strcpy`` (no length argument) is always eligible.
    # ``engine.copy_call_length_is_literal`` may be absent on lightweight mock
    # engines; treat its absence as "not literal" (conservative, preserves the
    # legacy co-location behavior for callers that do not provide it).
    length_is_literal = getattr(engine, "copy_call_length_is_literal", None)

    def _eligible(cs) -> bool:
        if length_is_literal is None:
            return True
        return not length_is_literal(cs.caller_function, cs.call_address, cs.target_name)

    copy_by_func: dict[str, list] = {}
    for cs in copy_calls:
        if not _eligible(cs):
            continue
        copy_by_func.setdefault(cs.caller_function, []).append(cs)

    # The "nearest" input source for the taint trace (earliest call address).
    src = min(source_calls, key=lambda c: c.call_address)

    findings: list[Finding] = []
    seen_funcs: set[str] = set()

    for func_name, allocs in alloc_by_func.items():
        if func_name not in copy_by_func:
            continue
        if func_name in seen_funcs:
            continue
        seen_funcs.add(func_name)

        alloc_cs = allocs[0]
        copy_cs = copy_by_func[func_name][0]

        trace = [
            TaintPoint(
                src.call_address,
                f"attacker-controlled value introduced via {src.target_name}()",
            ),
            TaintPoint(
                alloc_cs.call_address,
                f"heap buffer allocated via {alloc_cs.target_name}() — size may be tainted",
            ),
            TaintPoint(
                copy_cs.call_address,
                f"{copy_cs.target_name}() writes into heap buffer with independent length — "
                f"length may exceed allocation size",
            ),
        ]
        findings.append(
            Finding(
                cwe=787,
                function=func_name,
                address=copy_cs.call_address,
                evidence=(
                    f"{alloc_cs.target_name}() allocation and {copy_cs.target_name}() "
                    f"write co-located in {func_name}: independent tainted size and length "
                    f"arguments risk out-of-bounds heap write"
                ),
                taint_trace=trace,
                confidence="medium",
            )
        )
    return findings
