/*
 * CWE-338 fixture: Use of Cryptographically Weak PRNG.
 *
 * Generates a "security token" from the C standard library's predictable
 * generators. autopsy's CWE-338 check must flag each weak-PRNG call site:
 *   - srand()   : seeds the predictable rand() stream (here from time())  -> MEDIUM
 *   - rand()    : non-cryptographic, predictable PRNG                     -> MEDIUM
 *   - drand48() : 48-bit LCG, trivially invertible                        -> MEDIUM
 *
 * It must NOT flag a cryptographically secure source. The companion function
 * secure_token() uses getrandom() and must stay silent.
 *
 * Compiled with: see Makefile (gcc -O0 -fno-stack-protector -no-pie -g)
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* getrandom() lives in <sys/random.h>; declare it so the call resolves to the
 * `getrandom` symbol that autopsy must NOT flag, without requiring the header. */
extern long getrandom(void *buf, unsigned long buflen, unsigned int flags);

/* Secure token: uses the kernel CSPRNG. autopsy must report ZERO findings here. */
static unsigned secure_token(void) {
    unsigned t = 0;
    getrandom(&t, sizeof(t), 0);   /* CSPRNG: must not be flagged */
    return t;
}

/* Weak token: predictable across runs once the seed is known. */
static unsigned weak_token(void) {
    srand((unsigned)time(NULL));   /* CWE-338: seeds predictable rand() */
    unsigned a = (unsigned)rand(); /* CWE-338: predictable PRNG */
    double  b = drand48();         /* CWE-338: 48-bit LCG */
    return a ^ (unsigned)(b * 1000000.0);
}

int main(void) {
    unsigned weak = weak_token();
    unsigned safe = secure_token();
    printf("weak=%u safe=%u\n", weak, safe);
    return 0;
}
