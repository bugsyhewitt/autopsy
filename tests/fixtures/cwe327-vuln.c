/*
 * CWE-327 fixture: Use of a Broken or Risky Cryptographic Algorithm.
 *
 * Calls broken cryptographic primitives whose very use is the weakness:
 *   - MD5()       : chosen-prefix collisions are practical            -> HIGH
 *   - SHA1()      : SHAttered collision in 2017                       -> HIGH
 *   - EVP_md5()   : selects the broken MD5 hash via the EVP API       -> HIGH
 *   - EVP_des_cbc(): selects single DES, 56-bit key                   -> HIGH
 *
 * The check must flag each. It must NOT flag the modern replacements
 * (SHA256, EVP_sha256, EVP_aes_256_gcm) used in safe_hash()/safe_cipher().
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g -lcrypto)
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static void weak_hash(const unsigned char *buf, size_t n, unsigned char *out) {
    MD5(buf, n, out);   /* CWE-327: broken hash */
}

static void weak_sha1(const unsigned char *buf, size_t n, unsigned char *out) {
    SHA1(buf, n, out);  /* CWE-327: broken hash */
}

static const EVP_MD *weak_evp_hash(void) {
    return EVP_md5();   /* CWE-327: selects broken hash via EVP API */
}

static const EVP_CIPHER *weak_evp_cipher(void) {
    return EVP_des_cbc(); /* CWE-327: selects single DES */
}

static void safe_hash(const unsigned char *buf, size_t n, unsigned char *out) {
    SHA256(buf, n, out);            /* SAFE: strong hash, must NOT fire */
}

static const EVP_MD *safe_evp_hash(void) {
    return EVP_sha256();            /* SAFE: strong hash, must NOT fire */
}

static const EVP_CIPHER *safe_evp_cipher(void) {
    return EVP_aes_256_gcm();       /* SAFE: AEAD cipher, must NOT fire */
}

int main(void) {
    unsigned char buf[16] = {0};
    unsigned char digest[64] = {0};

    weak_hash(buf, sizeof(buf), digest);
    weak_sha1(buf, sizeof(buf), digest);
    const EVP_MD *m = weak_evp_hash();
    const EVP_CIPHER *c = weak_evp_cipher();

    safe_hash(buf, sizeof(buf), digest);
    const EVP_MD *sm = safe_evp_hash();
    const EVP_CIPHER *sc = safe_evp_cipher();

    return (int)(digest[0] ^ ((unsigned long)m & 0xff)
                          ^ ((unsigned long)c & 0xff)
                          ^ ((unsigned long)sm & 0xff)
                          ^ ((unsigned long)sc & 0xff));
}
