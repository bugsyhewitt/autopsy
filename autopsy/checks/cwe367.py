"""CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition.

Strategy (whole-program, call-site-driven): flag every function that *checks* a
filesystem path by name and then later *uses* a path by name, leaving a
time-of-check-to-time-of-use window. The canonical bug is ``access()`` before
``open()``: a setuid program asks ``access(path, W_OK)`` "may the *real* user
write here?", the check passes, and the program then ``open()``s the path with
its elevated privileges. An attacker who swaps ``path`` for a symlink in the
interval (winning the race) redirects the privileged write to a file the real
user could never have opened — the classic local privilege escalation. The same
window exists for any check→use pair that operates on a *name* rather than a
file descriptor: ``stat``/``lstat`` followed by ``open``/``fopen``/``creat``/
``unlink``/``rename``/``chmod``/``symlink`` and friends.

The fix is to operate on the object, not the name: ``open()`` once and then
``fstat``/``fchmod``/``faccessat(..., AT_EMPTY_PATH)`` on the returned
descriptor, or use ``openat`` with ``O_NOFOLLOW``. autopsy therefore keys the
*use* set on by-name functions only; the descriptor-based safe forms
(``fstat``/``fchmod`` on an ``fd``) are intentionally absent and never fire.

Like CWE-377 (insecure temp file) and CWE-676 (dangerous function), and unlike
the taint-flow checks (CWE-78/134), CWE-367 needs no attacker-input source: the
race is a structural property of the check→use sequence, not of a proven tainted
path. The detector is fully call-site-driven — it resolves direct calls by
symbol name and never inspects registers — so it is architecture-agnostic and
runs identically on x86_64 (``call``) and AArch64 (``bl``).

Zero-false-positive posture: a function that only checks (no following by-name
use) or only uses (no preceding check) is silent — both halves must be
co-located in the same function for a finding to fire. The engine helper
:meth:`AngrEngine.toctou_check_then_use_sequences` reports each check paired
with the first by-name use that follows it.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# A few high-signal pairings get a friendlier remediation hint; everything else
# falls back to the generic descriptor-based advice.
_FIX_HINTS: dict[tuple[str, str], str] = {
    ("access", "open"): "open() first, then check the returned fd, or use access(..., AT_EACCESS) on a descriptor",
    ("access", "open64"): "open() first, then check the returned fd",
    ("access", "fopen"): "open the file once and operate on the descriptor",
    ("stat", "open"): "open() the file and fstat() the returned descriptor",
    ("lstat", "open"): "open() with O_NOFOLLOW and fstat() the descriptor",
    ("stat", "unlink"): "operate on a descriptor (openat + O_NOFOLLOW) instead of re-resolving the path",
    ("lstat", "unlink"): "use unlinkat with the directory fd to avoid re-resolving the path",
}

_GENERIC_FIX = (
    "operate on a file descriptor (open once, then fstat/fchmod/faccessat on the "
    "fd) or use the *at() family with O_NOFOLLOW instead of re-resolving the path "
    "by name"
)


def run(engine) -> list[Finding]:
    sequences = engine.toctou_check_then_use_sequences()
    if not sequences:
        return []

    findings: list[Finding] = []
    for seq in sequences:
        check = seq["check_name"]
        use = seq["use_name"]
        func = seq["function"]
        check_addr = seq["check_address"]
        use_addr = seq["use_address"]

        fix = _FIX_HINTS.get((check, use), _GENERIC_FIX)
        evidence = (
            f"{check}() checks a path by name and {use}() then operates on a path "
            f"by name in {func}: an attacker who alters the path between the check "
            f"and the use (a TOCTOU race, e.g. a symlink swap) makes {use}() act on "
            f"a different object than {check}() vetted; {fix}"
        )
        findings.append(
            Finding(
                cwe=367,
                function=func,
                # The use is where the damage lands, so anchor the finding there.
                address=use_addr,
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        check_addr,
                        f"time-of-check: {check}() inspects the path by name",
                    ),
                    TaintPoint(
                        use_addr,
                        f"time-of-use: {use}() operates on the path by name "
                        f"(window between the two is the race)",
                    ),
                ],
                # The check→use sequence on a by-name path is a definitive
                # structural TOCTOU window. autopsy does not prove the two calls
                # reference the *same* path string (that would need full taint),
                # so this is a strong-but-not-certain signal -> medium confidence.
                confidence="medium",
            )
        )
    return findings
