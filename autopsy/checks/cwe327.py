"""CWE-327: Use of a Broken or Risky Cryptographic Algorithm.

Strategy (whole-program, call-site-driven): flag every call to a cryptographic
primitive whose algorithm is broken or risky by modern standards — MD2/MD4/MD5,
SHA-1, DES/3DES, RC4, RC2, and Blowfish. These primitives have public preimage,
collision or key-recovery attacks (MD5/SHA-1 collisions are routine; DES has a
56-bit key brute-forceable in hours; RC4 has practical biases broken by Bar-Mizrahi
and the NOMORE attack) and NIST SP 800-131A has formally disallowed them for
security purposes.

The check matches direct calls by symbol name into the common cryptographic
libraries — OpenSSL/libcrypto (``MD5``/``MD5_Init``/``SHA1``/``SHA1_Init``/
``DES_*``/``RC4``/``BF_*``), the legacy glibc ``crypt`` family, and the
high-level ``EVP_*`` constructors that take a named cipher/digest pointer
(``EVP_md5``/``EVP_sha1``/``EVP_des_cbc``/``EVP_rc4`` and their friends). Like
CWE-338 (weak PRNG), CWE-676 (dangerous function) and CWE-377 (insecure temp
file), CWE-327 needs no attacker-input source: the *use of the broken primitive
itself* is the weakness, exactly as MITRE classifies it. autopsy cannot prove
from the binary that the digest feeds a security decision (a program may use
MD5 purely for a non-security checksum), so the call is the structural red flag
and findings are reported at appropriate confidence.

This is a **call-site-driven** detector: it resolves direct calls by symbol
name and never inspects registers, so it is architecture-agnostic and runs on
every architecture autopsy can load (x86_64 and AArch64).

The detector deliberately does *not* flag the modern replacements
(``SHA256``/``SHA384``/``SHA512``/``SHA3_*``, ``EVP_sha256``/``EVP_sha3_256``,
``EVP_aes_*_gcm``, ``AES_*``, ``ChaCha20``/``EVP_chacha20_poly1305``,
``crypt_r`` with a modern ``$6$`` SHA-512 setting, ``argon2``/``bcrypt``/
``scrypt``): those are the forms users are told to migrate to, which is what
keeps the zero-false-positive line on the clean baseline.
"""

from __future__ import annotations

from autopsy.report import Finding, TaintPoint

# Why each entry is here:
#   - MD2/MD4/MD5: collision attacks are practical (Wang 2004; Stevens 2012
#     produced rogue X.509 certs from MD5 collisions). NIST SP 800-131A
#     disallowed for digital signatures.
#   - SHA-1: collision found by Google's SHAttered (2017) and the chosen-prefix
#     attack by Leurent-Peyrin (2020). Deprecated by NIST since 2011.
#   - DES (single): 56-bit key; brute-forced by EFF Deep Crack in 1998.
#     3DES (TDEA): Sweet32 (Bhargavan-Leurent 2016) — 64-bit block makes it
#     unsafe for any non-trivial volume of traffic; NIST disallowed for
#     encryption after 2023.
#   - RC4: biases known since Mantin-Shamir 2001; NOMORE attack against TLS
#     in 2015; RFC 7465 prohibits it in TLS.
#   - RC2: 64-bit block, related-key attacks; long deprecated.
#   - Blowfish (BF_*): 64-bit block; Sweet32 applies. Use AES.
# Maps symbol name -> (terse reason it's broken/risky, modern replacement).
_BROKEN: dict[str, tuple[str, str]] = {
    # OpenSSL legacy hash primitives — direct API.
    "MD2": ("MD2 is a broken hash (preimage and collision attacks since 2009)", "SHA-256 / SHA-3"),
    "MD2_Init": ("MD2 is a broken hash (preimage and collision attacks since 2009)", "SHA-256 / SHA-3"),
    "MD4": ("MD4 is a broken hash (full collisions in seconds since 2005)", "SHA-256 / SHA-3"),
    "MD4_Init": ("MD4 is a broken hash (full collisions in seconds since 2005)", "SHA-256 / SHA-3"),
    "MD5": (
        "MD5 is a broken hash (chosen-prefix collisions are practical; not safe for signatures or auth)",
        "SHA-256 / SHA-3 / BLAKE2",
    ),
    "MD5_Init": (
        "MD5 is a broken hash (chosen-prefix collisions are practical; not safe for signatures or auth)",
        "SHA-256 / SHA-3 / BLAKE2",
    ),
    "SHA1": (
        "SHA-1 is broken (SHAttered collision in 2017; chosen-prefix collision in 2020)",
        "SHA-256 / SHA-3 / BLAKE2",
    ),
    "SHA1_Init": (
        "SHA-1 is broken (SHAttered collision in 2017; chosen-prefix collision in 2020)",
        "SHA-256 / SHA-3 / BLAKE2",
    ),
    # OpenSSL legacy symmetric ciphers — direct API.
    "DES_encrypt1": ("single DES has a 56-bit key; brute-forced since 1998", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "DES_encrypt2": ("single DES has a 56-bit key; brute-forced since 1998", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "DES_encrypt3": ("3DES has a 64-bit block; Sweet32 makes it unsafe for nontrivial volume", "AES-128/AES-256 (GCM)"),
    "DES_ecb_encrypt": ("single DES has a 56-bit key; brute-forced since 1998", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "DES_cbc_encrypt": ("single DES has a 56-bit key; brute-forced since 1998", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "DES_ede3_cbc_encrypt": ("3DES has a 64-bit block; Sweet32 makes it unsafe for nontrivial volume", "AES-128/AES-256 (GCM)"),
    "DES_set_key": ("DES key schedule (uses single DES); single DES is brute-forceable", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "DES_set_key_unchecked": ("DES key schedule (uses single DES); single DES is brute-forceable", "AES-128/AES-256 (GCM or CTR+HMAC)"),
    "RC4": (
        "RC4 has practical biases (NOMORE attack 2015; RFC 7465 prohibits it in TLS)",
        "AES-128/AES-256-GCM or ChaCha20-Poly1305",
    ),
    "RC4_set_key": (
        "RC4 has practical biases (NOMORE attack 2015; RFC 7465 prohibits it in TLS)",
        "AES-128/AES-256-GCM or ChaCha20-Poly1305",
    ),
    "RC2_encrypt": ("RC2 has a 64-bit block and known related-key attacks; long deprecated", "AES-128/AES-256 (GCM)"),
    "RC2_cbc_encrypt": ("RC2 has a 64-bit block and known related-key attacks; long deprecated", "AES-128/AES-256 (GCM)"),
    "BF_encrypt": ("Blowfish has a 64-bit block; Sweet32 applies", "AES-128/AES-256 (GCM)"),
    "BF_cbc_encrypt": ("Blowfish has a 64-bit block; Sweet32 applies", "AES-128/AES-256 (GCM)"),
    "BF_set_key": ("Blowfish has a 64-bit block; Sweet32 applies", "AES-128/AES-256 (GCM)"),
    # OpenSSL EVP_* constructors that select a broken/risky primitive by name.
    # A call to EVP_md5() / EVP_sha1() / EVP_des_*() / EVP_rc4() returns the
    # algorithm pointer that the caller then feeds to EVP_DigestInit_ex() or
    # EVP_CipherInit_ex() — naming a broken primitive is the weakness, even
    # without the surrounding context.
    "EVP_md2": ("EVP_md2() selects the broken MD2 hash", "EVP_sha256 / EVP_sha3_256 / EVP_blake2b512"),
    "EVP_md4": ("EVP_md4() selects the broken MD4 hash", "EVP_sha256 / EVP_sha3_256 / EVP_blake2b512"),
    "EVP_md5": ("EVP_md5() selects the broken MD5 hash", "EVP_sha256 / EVP_sha3_256 / EVP_blake2b512"),
    "EVP_md5_sha1": ("EVP_md5_sha1() selects a combined MD5+SHA1 hash; both halves are broken", "EVP_sha256 / EVP_sha3_256"),
    "EVP_sha1": ("EVP_sha1() selects the broken SHA-1 hash", "EVP_sha256 / EVP_sha3_256 / EVP_blake2b512"),
    "EVP_des_cbc": ("EVP_des_cbc() selects single DES; 56-bit key brute-forced since 1998", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ecb": ("EVP_des_ecb() selects single DES; ECB also leaks plaintext structure", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_cfb": ("EVP_des_cfb() selects single DES; 56-bit key brute-forced since 1998", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ofb": ("EVP_des_ofb() selects single DES; 56-bit key brute-forced since 1998", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ede": ("EVP_des_ede() selects 2-key 3DES; 64-bit block (Sweet32) and reduced security margin", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ede_cbc": ("EVP_des_ede_cbc() selects 2-key 3DES; 64-bit block (Sweet32) and reduced security margin", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ede3": ("EVP_des_ede3() selects 3-key 3DES; 64-bit block makes it Sweet32-vulnerable", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_des_ede3_cbc": ("EVP_des_ede3_cbc() selects 3-key 3DES; 64-bit block makes it Sweet32-vulnerable", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_rc4": ("EVP_rc4() selects RC4; practical biases (NOMORE 2015; RFC 7465 prohibits in TLS)", "EVP_aes_128_gcm / EVP_chacha20_poly1305"),
    "EVP_rc4_40": ("EVP_rc4_40() selects 40-bit RC4; export-grade key length, trivially broken", "EVP_aes_128_gcm / EVP_chacha20_poly1305"),
    "EVP_rc2_cbc": ("EVP_rc2_cbc() selects RC2; 64-bit block and related-key attacks", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_rc2_40_cbc": ("EVP_rc2_40_cbc() selects 40-bit RC2; export-grade, trivially broken", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_bf_cbc": ("EVP_bf_cbc() selects Blowfish; 64-bit block (Sweet32)", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    "EVP_bf_ecb": ("EVP_bf_ecb() selects Blowfish; 64-bit block (Sweet32) and ECB plaintext leakage", "EVP_aes_128_gcm / EVP_aes_256_gcm"),
    # Legacy glibc password hashing. crypt() with the historic DES setting
    # (two-character salt, no $id$ prefix) hashes with a 56-bit-key variant of
    # DES; even the MD5 variant ($1$) is now considered too fast for password
    # hashing. We flag the symbol; the strong replacements (argon2/bcrypt/
    # crypt with $6$ SHA-512 setting via the same crypt() symbol) require the
    # caller to choose the setting — the call alone cannot prove which.
    "crypt": (
        "crypt() defaults to DES-based password hashing; even its MD5/SHA variants are too fast for password storage",
        "argon2 / bcrypt / scrypt (or libxcrypt with $argon2id$/$7$/$6$ setting)",
    ),
    "crypt_r": (
        "crypt_r() inherits crypt()'s legacy algorithm selection; the DES and MD5 variants are unsafe",
        "argon2 / bcrypt / scrypt (or libxcrypt with $argon2id$/$7$/$6$ setting)",
    ),
}

# MD5/SHA-1 collisions and DES brute force are textbook-broken and the call
# alone proves the broken primitive is in use; high confidence on these.
# The other primitives are broken too but in some legacy interop scenarios
# (verifying an old signature, reading a legacy archive) the call cannot be
# avoided, so they ship at medium to allow triage to keep the obvious
# misuses (MD5/SHA1/DES) at the top of the list. crypt()/crypt_r() are
# medium because the same symbol can host a strong $argon2id$/$7$ setting
# that the binary alone cannot distinguish.
_HIGH_CONFIDENCE = frozenset({
    "MD5", "MD5_Init", "SHA1", "SHA1_Init",
    "EVP_md5", "EVP_sha1", "EVP_md5_sha1",
    "DES_encrypt1", "DES_encrypt2", "DES_ecb_encrypt", "DES_cbc_encrypt",
    "DES_set_key", "DES_set_key_unchecked",
    "EVP_des_cbc", "EVP_des_ecb", "EVP_des_cfb", "EVP_des_ofb",
    "RC4", "RC4_set_key", "EVP_rc4", "EVP_rc4_40",
    "EVP_rc2_40_cbc",
})


def run(engine) -> list[Finding]:
    call_sites = engine.call_sites_to(set(_BROKEN))
    if not call_sites:
        return []
    findings: list[Finding] = []
    for cs in call_sites:
        reason, replacement = _BROKEN[cs.target_name]
        confidence = "high" if cs.target_name in _HIGH_CONFIDENCE else "medium"
        evidence = (
            f"call to broken/risky cryptographic primitive {cs.target_name}() in "
            f"{cs.caller_function}: {reason}; prefer {replacement}"
        )
        findings.append(
            Finding(
                cwe=327,
                function=cs.caller_function,
                address=cs.call_address,
                evidence=evidence,
                taint_trace=[
                    TaintPoint(
                        cs.call_address,
                        f"use of broken/risky cryptographic primitive {cs.target_name}()",
                    )
                ],
                confidence=confidence,
            )
        )
    return findings
