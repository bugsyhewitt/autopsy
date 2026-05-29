"""CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG).

Strategy (whole-program, call-site-driven): flag every call to a libc
random-number function whose output is *not* cryptographically secure — a PRNG
that is fast and statistically uniform but fully predictable to an attacker who
recovers (or guesses) its seed. The canonical offenders are the C standard
library generators: ``rand``/``random`` (and the reentrant ``rand_r``/
``random_r``), the BSD ``drand48`` family (``drand48``/``lrand48``/``mrand48``/
``erand48``/``nrand48``/``jrand48`` and their ``*_r`` variants), and the seeders
that pair with them (``srand``/``srandom``/``srand48``/``seed48``/``lcong48``).
A 48-bit linear-congruential generator (the drand48 family) and glibc's additive
feedback ``random`` are trivially reversible: an attacker who observes a few
outputs — or simply knows the program seeded with ``time(NULL)`` — can predict
all future values. Using any of these to derive a token, session id, nonce, key,
salt or password is the weakness CWE-338 names.

Like CWE-676 and CWE-377 (and unlike the taint-flow checks CWE-78/134), CWE-338
needs no attacker-input source: the weakness is the *use of a non-CSPRNG in a
security context*. autopsy cannot prove the output is used for security from the
binary alone, so — exactly as the MITRE guidance frames it — the call to a weak
PRNG is itself the structural red flag. This makes the detector fully
call-site-driven and therefore architecture-agnostic: it resolves direct calls
by symbol name and never inspects registers, so it runs on every architecture
autopsy can load (x86_64 and AArch64).

The detector deliberately does *not* flag the cryptographically secure sources
users should migrate to — ``getrandom``, ``arc4random``/``arc4random_buf``/
``arc4random_uniform``, and a read from ``/dev/urandom``. Flagging those would
defeat the zero-false-positive guarantee on well-written code.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Cryptographically weak libc PRNG functions, mapped to the terse reason they
# are insecure and the secure replacement users should migrate to. Keys are the
# symbol names that show up as direct-call targets in an ELF. The secure CSPRNG
# sources (getrandom / arc4random* / /dev/urandom) are intentionally absent —
# flagging them would be a false positive.
_WEAK: dict[str, tuple[str, str]] = {
    # ISO C rand(): a small-period, fully predictable generator.
    "rand": (
        "rand() is a predictable non-cryptographic PRNG; its output can be "
        "reconstructed from the seed",
        "getrandom / arc4random",
    ),
    "rand_r": (
        "rand_r() is a predictable non-cryptographic PRNG; its output can be "
        "reconstructed from the seed",
        "getrandom / arc4random",
    ),
    # glibc random(): additive-feedback, reversible from a handful of outputs.
    "random": (
        "random() is a predictable non-cryptographic PRNG reversible from a "
        "few outputs",
        "getrandom / arc4random",
    ),
    "random_r": (
        "random_r() is a predictable non-cryptographic PRNG reversible from a "
        "few outputs",
        "getrandom / arc4random",
    ),
    # BSD drand48 family: a 48-bit linear-congruential generator, trivially
    # invertible.
    "drand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    "erand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    "lrand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    "nrand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    "mrand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    "jrand48": (
        "the drand48 family is a 48-bit LCG; its state is trivially recovered "
        "from output",
        "getrandom / arc4random",
    ),
    # Seeders. Seeding a weak PRNG is itself the predictable-randomness pattern;
    # seeding from time() is the classic CWE-338 instance.
    "srand": (
        "srand() seeds the predictable rand() PRNG (often from time(), making "
        "the stream guessable)",
        "getrandom / arc4random (no manual seeding)",
    ),
    "srandom": (
        "srandom() seeds the predictable random() PRNG (often from time(), "
        "making the stream guessable)",
        "getrandom / arc4random (no manual seeding)",
    ),
    "srand48": (
        "srand48() seeds the predictable drand48 LCG, making the stream "
        "guessable",
        "getrandom / arc4random (no manual seeding)",
    ),
    "seed48": (
        "seed48() seeds the predictable drand48 LCG, making the stream "
        "guessable",
        "getrandom / arc4random (no manual seeding)",
    ),
    "lcong48": (
        "lcong48() sets the predictable drand48 LCG state, making the stream "
        "guessable",
        "getrandom / arc4random (no manual seeding)",
    ),
}


def run(engine) -> list[Finding]:
    call_sites = engine.call_sites_to(set(_WEAK))
    if not call_sites:
        return []
    findings: list[Finding] = []
    for cs in call_sites:
        reason, replacement = _WEAK[cs.target_name]
        # Every function in the set is a definitive non-CSPRNG, so the call is a
        # certain use of weak randomness. But autopsy cannot prove from the
        # binary that the output feeds a security decision (a program may use
        # rand() purely for a game or a load-balancing jitter), so the finding
        # is medium confidence: a strong structural signal, not a proven
        # security-relevant taint path.
        confidence = "medium"
        evidence = (
            f"call to weak PRNG {cs.target_name}() in "
            f"{cs.caller_function}: {reason}; prefer {replacement}"
        )
        findings.append(
            Finding(
                cwe=338,
                function=cs.caller_function,
                address=cs.call_address,
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        cs.call_address,
                        f"use of cryptographically weak PRNG {cs.target_name}()",
                    )
                ],
                confidence=confidence,
            )
        )
    return findings
