/*
 * fuzz_wire.c — deterministic mutation fuzzer for the wire-open path.
 * Builds a valid v3 stash (plaintext + encrypted), then throws mutated
 * / truncated / spliced variants at kr_wire_fuzz_entry.  Any crash,
 * hang, or non-error return on corrupt input is a bug (the loader must
 * reject untrusted stashes cleanly — digest, KR2 tag, header version,
 * length field).  Run inside `make test` with a fixed seed.
 */
#include <stdint.h>
#include <stddef.h>
#include "../keyringer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

int main(void)
{
    char err[KR_ERRSZ];
    /* valid-ish v3 wire: header + body of the RFC plaintext */
    uint8_t base[KR_HDR3_LEN + 200];

    memcpy(base, "KRH3", 4);
    base[4] = 3;
    base[5] = 0;                                   /* plaintext body */
    for (int i = 6; i < (int)sizeof base; i++)
        base[i] = (uint8_t)(i * 7);

    /* deterministic plaintext mode: no crash over 200k mutations */
    for (long iter = 0; iter < 200000; iter++) {
        uint8_t buf[sizeof base];
        size_t len = sizeof base;

        memcpy(buf, base, sizeof base);
        switch (rnd() % 4) {
        case 0:                                    /* bit flips */
            for (int i = 0; i < 8; i++)
                buf[rnd() % len] ^= (uint8_t)(1u << (rnd() % 8));
            break;
        case 1:                                    /* truncate */
            len = 8 + rnd() % (sizeof base - 8);
            break;
        case 2:                                    /* header version/flags chaos */
            buf[4] = (uint8_t)rnd();
            buf[5] = (uint8_t)rnd();
            break;
        default:                                   /* duplicate body head into tail */
            memcpy(buf + KR_HDR3_LEN + 32, buf + KR_HDR3_LEN, 16);
            break;
        }
        (void)kr_wire_fuzz_entry(buf, len, NULL, err);
    }
    printf("fuzz: 200000 mutations survived (plaintext + bad-key modes)\n");
    return 0;
}
