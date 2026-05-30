"""CWE-125: Out-of-Bounds Read — heap buffer over-read via malloc+bulk-read taint mismatch.

Strategy (whole-program): detect the classic dual of CWE-787. A heap buffer
is allocated with ``malloc``/``calloc``/``realloc`` (size = N) and the same
function then *reads* from it (or from another buffer alongside it) using a
bulk-read sink — ``memcmp``/``strncmp``/``strncasecmp``/``memchr`` — whose
length argument (M) is *not* a compile-time literal. When N and M both flow
from attacker-controlled input, M may exceed N and the read walks past the
allocated region: an out-of-bounds heap read.

This is the read-side complement of the CWE-787 (Out-of-Bounds Write) detector
and uses the same co-location + length-literal-suppression heuristic, just
against read-shaped sinks instead of write-shaped ones. CWE-125 is rank #6 on
the 2025 MITRE/CISA CWE Top 25 with 12 CISA KEV entries (actively exploited).

Detection steps:
  1. Find calls to ``malloc``/``calloc``/``realloc``/``reallocarray``.
  2. For each allocator call, check whether the same function also contains a
     call to a bulk-read function: ``memcmp``, ``strncmp``, ``strncasecmp``,
     ``memchr``.
  3. Require at least one *eligible* read sink in that function — one whose
     length argument is NOT a compile-time literal. A read with a literal
     length (e.g. ``memcmp(p, q, 4)``) has a fixed, attacker-independent read
     extent and cannot produce a tainted out-of-bounds read, so it is
     excluded.  This mirrors the CWE-787 suppression that fixed the
     clean-baseline false positive.
  4. Confirm that the program has at least one attacker-controlled input
     source in scope (same ``_SOURCES`` set as CWE-787 / CWE-190).
  5. Flag with severity HIGH, confidence ``"medium"`` — the alloc/read
     mismatch heuristic catches the structural pattern but cannot prove at
     this level of analysis that M > N on all paths.

Confidence rationale:
  ``"medium"`` — we confirm the co-location of an allocator and a non-literal
  bulk-read sink AND the presence of an input source, but we do not
  symbolically evaluate whether M > N. That would require full heap-size
  tracking (a post-v0.1 direction shared with CWE-787).

[Worker decision: function-scope co-location heuristic — read-side]
  We reuse the same co-location heuristic that CWE-787 settled on after the
  Rotation 9 clean-baseline tuning. A full def-use chain from the malloc
  return value through the read pointer would be more precise but fragile
  in CFGFast; the structural alloc+read+tainted-length pattern is the
  highest-value low-risk signal at this analysis tier.

[Worker decision: literal-length suppression]
  The check delegates to ``engine.copy_call_length_is_literal`` — the same
  helper CWE-787 uses — extended to recognize the new read sinks. The
  AAPCS64/SysV calling conventions place the byte-count argument of every
  sink we care about in the same register (``rdx`` / ``x2``), so the helper
  generalizes cleanly to ``memcmp``/``strncmp``/``strncasecmp``/``memchr``.
  Engines without that helper (lightweight mocks) keep the legacy
  "everything is eligible" behavior — conservative but safe.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

_ALLOCATORS = {"malloc", "calloc", "realloc", "reallocarray"}

# Bulk-read sinks whose 3rd argument is a byte-count (``size_t n``). Each is a
# read-side analogue of the CWE-787 write sinks: the read extent depends on a
# runtime length that, if attacker-controlled and larger than the allocation,
# walks off the end of the buffer. ``memmem`` is deliberately omitted — it
# carries two lengths and would need a separate sink shape.
_READ_SINKS = {"memcmp", "strncmp", "strncasecmp", "memchr"}

# Attacker-controlled input sources (same set as CWE-787 / CWE-190).
_SOURCES = {"fgets", "gets", "read", "scanf", "__isoc99_scanf", "atoi", "strtol", "atol"}


def run(engine) -> list[Finding]:
    """Detect malloc + non-literal-length bulk-read co-location with a taint source.

    Returns one finding per function that contains both an allocator call and
    a bulk-read call with a non-literal length, provided the program has at
    least one attacker-controlled input source.
    """
    alloc_calls = engine.call_sites_to(_ALLOCATORS)
    if not alloc_calls:
        return []
    source_calls = engine.call_sites_to(_SOURCES)
    if not source_calls:
        return []
    read_calls = engine.call_sites_to(_READ_SINKS)
    if not read_calls:
        return []

    # Group allocator calls and read calls by containing function.
    alloc_by_func: dict[str, list] = {}
    for cs in alloc_calls:
        alloc_by_func.setdefault(cs.caller_function, []).append(cs)

    # Only read sinks whose length argument is NOT a provable compile-time
    # literal are eligible. ``engine.copy_call_length_is_literal`` may be
    # absent on lightweight mock engines; treat its absence as "not literal"
    # (conservative, preserves legacy co-location behavior for callers that do
    # not provide it).
    length_is_literal = getattr(engine, "copy_call_length_is_literal", None)

    def _eligible(cs) -> bool:
        if length_is_literal is None:
            return True
        return not length_is_literal(cs.caller_function, cs.call_address, cs.target_name)

    read_by_func: dict[str, list] = {}
    for cs in read_calls:
        if not _eligible(cs):
            continue
        read_by_func.setdefault(cs.caller_function, []).append(cs)

    # The "nearest" input source for the taint trace (earliest call address).
    src = min(source_calls, key=lambda c: c.call_address)

    findings: list[Finding] = []
    seen_funcs: set[str] = set()

    for func_name, allocs in alloc_by_func.items():
        if func_name not in read_by_func:
            continue
        if func_name in seen_funcs:
            continue
        seen_funcs.add(func_name)

        alloc_cs = allocs[0]
        read_cs = read_by_func[func_name][0]

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
                read_cs.call_address,
                f"{read_cs.target_name}() reads from heap buffer with independent length — "
                f"length may exceed allocation size",
            ),
        ]
        findings.append(
            Finding(
                cwe=125,
                function=func_name,
                address=read_cs.call_address,
                evidence=(
                    f"{alloc_cs.target_name}() allocation and {read_cs.target_name}() "
                    f"read co-located in {func_name}: independent tainted size and length "
                    f"arguments risk out-of-bounds heap read"
                ),
                taint_trace=trace,
                confidence="medium",
            )
        )
    return findings
