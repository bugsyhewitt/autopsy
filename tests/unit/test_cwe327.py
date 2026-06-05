"""Fast unit tests for the CWE-327 broken/risky cryptographic algorithm detector.

angr-free: uses a mock engine returning pre-canned CallSites.
"""

from __future__ import annotations

from autopsy.checks import cwe327
from autopsy.engine import CallSite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cs(target_name, caller_function="main", call_address=0x400500, block_addr=0x400500):
    return CallSite(
        caller_function=caller_function,
        call_address=call_address,
        target_name=target_name,
        block_addr=block_addr,
    )


def _make_engine(call_sites):
    """Mock engine: call_sites_to returns only calls whose target is queried."""

    class _E:
        def __init__(self):
            self._calls = call_sites

        def call_sites_to(self, names):
            return [cs for cs in self._calls if cs.target_name in names]

    return _E()


# ---------------------------------------------------------------------------
# No-findings cases
# ---------------------------------------------------------------------------


def test_no_findings_on_empty_program():
    """A program with no crypto calls -> no findings."""
    assert cwe327.run(_make_engine([])) == []


def test_no_findings_on_safe_crypto_only():
    """Programs using only modern safe primitives -> zero findings."""
    safe_names = [
        "SHA256", "SHA384", "SHA512",
        "EVP_sha256", "EVP_sha3_256", "EVP_aes_256_gcm",
        "EVP_chacha20_poly1305",
    ]
    engine = _make_engine([_make_cs(n) for n in safe_names])
    assert cwe327.run(engine) == []


# ---------------------------------------------------------------------------
# HIGH confidence: MD5, SHA-1, DES, RC4 (direct calls)
# ---------------------------------------------------------------------------


def test_md5_direct_high_confidence():
    """MD5() is a broken hash -> HIGH confidence finding."""
    findings = cwe327.run(_make_engine([_make_cs("MD5", call_address=0x401100)]))
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == 327
    assert f.address == 0x401100
    assert f.confidence == "high"
    assert "MD5" in f.evidence
    assert "collision" in f.evidence.lower() or "broken" in f.evidence.lower()


def test_md5_init_high_confidence():
    """MD5_Init() is the incremental MD5 API -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("MD5_Init")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "MD5" in f.evidence


def test_sha1_direct_high_confidence():
    """SHA1() is broken (SHAttered collision) -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("SHA1")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "SHA-1" in f.evidence or "SHA1" in f.evidence


def test_sha1_init_high_confidence():
    """SHA1_Init() is the incremental SHA-1 API -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("SHA1_Init")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_des_encrypt1_high_confidence():
    """DES_encrypt1() operates with a 56-bit key -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("DES_encrypt1")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "DES" in f.evidence or "56-bit" in f.evidence


def test_des_cbc_encrypt_high_confidence():
    """DES_cbc_encrypt() is single DES in CBC mode -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("DES_cbc_encrypt")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_rc4_direct_high_confidence():
    """RC4() has practical biases (NOMORE attack) -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("RC4")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "RC4" in f.evidence


def test_rc4_set_key_high_confidence():
    """RC4_set_key() initialises the broken RC4 stream cipher -> HIGH."""
    f = cwe327.run(_make_engine([_make_cs("RC4_set_key")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


# ---------------------------------------------------------------------------
# HIGH confidence: EVP_* constructors for broken algorithms
# ---------------------------------------------------------------------------


def test_evp_md5_high_confidence():
    """EVP_md5() selects the broken MD5 hash -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_md5")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "EVP_md5" in f.evidence or "MD5" in f.evidence


def test_evp_sha1_high_confidence():
    """EVP_sha1() selects the broken SHA-1 hash -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_sha1")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_evp_md5_sha1_high_confidence():
    """EVP_md5_sha1() combines two broken hashes -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_md5_sha1")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_evp_des_cbc_high_confidence():
    """EVP_des_cbc() selects single DES (56-bit key) -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_des_cbc")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_evp_des_ecb_high_confidence():
    """EVP_des_ecb() selects single DES in ECB mode -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_des_ecb")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    # ECB mode also leaks plaintext structure
    assert "ECB" in f.evidence or "single DES" in f.evidence or "56-bit" in f.evidence


def test_evp_rc4_high_confidence():
    """EVP_rc4() selects RC4 -> HIGH confidence."""
    f = cwe327.run(_make_engine([_make_cs("EVP_rc4")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


def test_evp_rc4_40_high_confidence():
    """EVP_rc4_40() is export-grade 40-bit RC4, trivially broken -> HIGH."""
    f = cwe327.run(_make_engine([_make_cs("EVP_rc4_40")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"
    assert "40" in f.evidence or "export" in f.evidence.lower()


def test_evp_rc2_40_cbc_high_confidence():
    """EVP_rc2_40_cbc() is export-grade RC2, trivially broken -> HIGH."""
    f = cwe327.run(_make_engine([_make_cs("EVP_rc2_40_cbc")]))[0]
    assert f.cwe == 327
    assert f.confidence == "high"


# ---------------------------------------------------------------------------
# MEDIUM confidence: 3DES, MD2/MD4, Blowfish, RC2, crypt, crypt_r
# ---------------------------------------------------------------------------


def test_des_ede3_cbc_medium_confidence():
    """DES_ede3_cbc_encrypt() is 3DES (Sweet32) -> MEDIUM confidence."""
    f = cwe327.run(_make_engine([_make_cs("DES_ede3_cbc_encrypt")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"
    assert "Sweet32" in f.evidence or "3DES" in f.evidence or "64-bit" in f.evidence


def test_md2_medium_confidence():
    """MD2 is a broken hash but less common -> MEDIUM confidence."""
    f = cwe327.run(_make_engine([_make_cs("MD2")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"
    assert "MD2" in f.evidence


def test_md4_medium_confidence():
    """MD4 has full collision in seconds -> MEDIUM confidence."""
    f = cwe327.run(_make_engine([_make_cs("MD4")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"


def test_blowfish_encrypt_medium_confidence():
    """BF_encrypt() uses Blowfish 64-bit block (Sweet32) -> MEDIUM."""
    f = cwe327.run(_make_engine([_make_cs("BF_encrypt")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"
    assert "Blowfish" in f.evidence or "Sweet32" in f.evidence or "BF" in f.evidence


def test_blowfish_cbc_medium_confidence():
    """BF_cbc_encrypt() is Blowfish in CBC mode -> MEDIUM confidence."""
    f = cwe327.run(_make_engine([_make_cs("BF_cbc_encrypt")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"


def test_crypt_medium_confidence():
    """crypt() defaults to DES-based password hashing -> MEDIUM confidence."""
    f = cwe327.run(_make_engine([_make_cs("crypt")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"
    assert "crypt" in f.evidence


def test_crypt_r_medium_confidence():
    """crypt_r() inherits crypt's legacy algorithm selection -> MEDIUM."""
    f = cwe327.run(_make_engine([_make_cs("crypt_r")]))[0]
    assert f.cwe == 327
    assert f.confidence == "medium"


# ---------------------------------------------------------------------------
# Finding contract, taint trace, serialization
# ---------------------------------------------------------------------------


def test_finding_has_correct_cwe():
    """Every finding must carry cwe == 327."""
    for name in ("MD5", "SHA1", "EVP_md5", "EVP_des_cbc", "BF_encrypt", "crypt"):
        f = cwe327.run(_make_engine([_make_cs(name)]))[0]
        assert f.cwe == 327, f"Expected cwe=327 for {name}, got {f.cwe}"


def test_finding_has_one_taint_trace_point():
    """The taint trace for a broken-crypto use is the call site itself."""
    trace = cwe327.run(_make_engine([_make_cs("MD5")]))[0].taint_trace
    assert len(trace) == 1
    assert "MD5" in trace[0].description


def test_finding_serializes_correctly():
    """to_dict() produces the required contract fields including confidence."""
    d = cwe327.run(_make_engine([_make_cs("SHA1", call_address=0x401200)]))[0].to_dict()
    assert d["cwe"] == 327
    assert d["function"] == "main"
    assert d["address"] == "0x401200"
    assert isinstance(d["taint_trace"], list)
    assert len(d["taint_trace"]) == 1
    assert d["evidence"]
    assert d["confidence"] == "high"


def test_evidence_names_replacement():
    """Evidence steers the user to a modern secure replacement."""
    f = cwe327.run(_make_engine([_make_cs("MD5")]))[0]
    assert "SHA-256" in f.evidence or "SHA-3" in f.evidence or "BLAKE2" in f.evidence


def test_multiple_broken_calls_each_flagged():
    """MD5 + SHA1 + EVP_des_cbc -> three distinct findings."""
    engine = _make_engine(
        [
            _make_cs("MD5", caller_function="hash_data", call_address=0x401100),
            _make_cs("SHA1", caller_function="sign_data", call_address=0x401200),
            _make_cs("EVP_des_cbc", caller_function="encrypt_data", call_address=0x401300),
        ]
    )
    findings = cwe327.run(engine)
    assert len(findings) == 3
    addrs = {f.address for f in findings}
    assert addrs == {0x401100, 0x401200, 0x401300}
    assert all(f.cwe == 327 for f in findings)
    assert all(f.confidence == "high" for f in findings)


def test_caller_function_preserved():
    """The caller function name from the CallSite is preserved in the finding."""
    f = cwe327.run(_make_engine([_make_cs("RC4", caller_function="encrypt_session")]))[0]
    assert f.function == "encrypt_session"


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_cwe327_registered_in_checks():
    """CWE-327 must be in the global CHECKS registry."""
    from autopsy.checks import CHECKS

    assert 327 in CHECKS
    assert CHECKS[327] is cwe327.run


def test_cwe327_in_scope_supported():
    """CWE-327 must appear in SUPPORTED_CWES and VALID_TOKENS."""
    from autopsy.scope import SUPPORTED_CWES, VALID_TOKENS

    assert 327 in SUPPORTED_CWES
    assert "327" in VALID_TOKENS


def test_cwe327_in_catalog():
    """CWE-327 must carry catalog metadata for --list-checks and SARIF."""
    from autopsy.scope import CWE_CATALOG, list_checks

    assert 327 in CWE_CATALOG
    assert CWE_CATALOG[327]["short"] == "Broken/Risky Crypto"
    cat = {c["cwe"] for c in list_checks()}
    assert 327 in cat


def test_cwe327_is_arch_agnostic():
    """CWE-327 is call-site-driven, so it must run on AArch64 too."""
    from autopsy.engine import AngrEngine

    assert 327 in AngrEngine._ARCH_AGNOSTIC_CHECKS


def test_resolve_checks_327():
    """resolve_checks('327') resolves to exactly [327]."""
    from autopsy.scope import resolve_checks

    assert resolve_checks("327") == [327]
