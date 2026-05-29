"""CWE-732: Incorrect Permission Assignment for Critical Resource.

Strategy (whole-program, register-level): flag every permission-setting call
whose mode argument is a compile-time immediate that grants write access beyond
the owner — the classic ``chmod(path, 0777)`` / ``chmod(path, 0666)`` mistake —
and every ``umask`` call whose immediate mask fails to strip the group/other
write bits (e.g. ``umask(0)``). Both make a resource (or every file the process
subsequently creates) writable by users other than its owner, which is exactly
the weakness CWE-732 names: an attacker with a local account can tamper with a
config file, a key, a log, or a setuid helper that should have been owner-only.

The mode/mask is read directly out of the call's argument register. The register
mapping is per-architecture — SysV x86_64 (``rsi`` for ``chmod``/``fchmod``/
``lchmod``, ``rdx`` for ``fchmodat``, ``rdi`` for ``umask``) and AAPCS64 AArch64
(``x1`` for ``chmod``/``fchmod``/``lchmod``, ``x2`` for ``fchmodat``, ``x0`` for
``umask``). The engine helpers :meth:`AngrEngine.chmod_calls_with_permissive_mode`
and :meth:`AngrEngine.umask_calls_with_permissive_mask` resolve the immediate by
walking back from the call site through the (small, -O0) instruction window,
handling both the x86_64 ``mov esi, 0x1ff`` form and the AArch64 ``mov w1, #0x1ff``
form (plus the ``mov w0, wzr`` zero-register encoding of ``umask(0)``).

Zero-false-positive posture: a mode/mask that is *computed at runtime* (loaded
from a stack slot or another register) has an unknown value, so it is never
flagged — only provably-permissive compile-time literals fire. A restrictive
``chmod(path, 0600)`` sets neither group- nor world-write and is silent, and a
``umask(0o077)`` / ``umask(0o022)`` that strips both group- and world-write is
silent too. Unlike the taint-flow checks (CWE-78/134), CWE-732 needs no
attacker-input source: an over-permissive permission literal is the weakness
itself regardless of any input path — exactly how MITRE frames CWE-732.

x86_64 (AMD64) and AArch64 (ARM64): the mode/mask-argument register reasoning is
arch-aware (it knows both the SysV and AAPCS64 argument registers and the per-arch
immediate-move encoding), so unlike the other register-level checks CWE-732 runs
on AArch64 too. It is therefore included in the engine's arch-agnostic check set
and is *not* skipped on AArch64. The engine helpers return nothing on any other
architecture (e.g. MIPS/PPC), so the check is silent there.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint


def _fmt_mode(mode: int) -> str:
    """Render a permission integer as a familiar octal literal (e.g. 0o777)."""
    return f"0o{mode:o}"


def _which_bits(mode: int) -> str:
    """Describe which dangerous bits a mode sets, in human terms."""
    parts = []
    if mode & 0o020:
        parts.append("group-write")
    if mode & 0o002:
        parts.append("world-write")
    return " and ".join(parts) if parts else "non-owner write"


def run(engine) -> list[Finding]:
    findings: list[Finding] = []

    # chmod/fchmod/lchmod/fchmodat with a permissive immediate mode.
    for site in engine.chmod_calls_with_permissive_mode():
        mode = site["mode"]
        sink = site["sink_name"]
        evidence = (
            f"{sink}() sets mode {_fmt_mode(mode)} in {site['function']}: grants "
            f"{_which_bits(mode)} access, making the resource writable beyond its "
            f"owner; restrict to 0o600/0o644 (owner-write only)"
        )
        findings.append(
            Finding(
                cwe=732,
                function=site["function"],
                address=site["address"],
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        site["address"],
                        f"{sink}() called with over-permissive mode {_fmt_mode(mode)}",
                    )
                ],
                # A compile-time literal that sets a group/other write bit is a
                # definitive over-permissive assignment -> high confidence.
                confidence="high",
            )
        )

    # umask with a mask that fails to strip group/other write.
    for site in engine.umask_calls_with_permissive_mask():
        mask = site["mode"]
        evidence = (
            f"umask({_fmt_mode(mask)}) in {site['function']} does not mask off "
            f"group/other write: files this process creates can be "
            f"{_which_bits(0o022 & ~mask)} writable; use umask(0o077) or at least "
            f"umask(0o022)"
        )
        findings.append(
            Finding(
                cwe=732,
                function=site["function"],
                address=site["address"],
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        site["address"],
                        f"umask({_fmt_mode(mask)}) leaves group/other write unmasked",
                    )
                ],
                # umask is a process-wide policy rather than a specific resource;
                # the over-permissive mask is a real weakness but its impact
                # depends on what files are later created -> medium confidence.
                confidence="medium",
            )
        )

    return findings
