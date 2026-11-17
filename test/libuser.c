/*
 * test/libuser.c — trivial libkeyringer consumer.
 *
 * Proves the `make lib` target: links -lkeyringer (shared) and drives
 * kr_version(), kr_selftest(), kr_stash() and kr_load_revoke() directly.
 * The library never prints and never exits — every diagnostic comes
 * back through err[]; the log hook is intentionally left silent here.
 */
#include "keyringer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char err[KR_ERRSZ];

    printf("libkeyringer: %s\n", kr_version());

    if (kr_selftest(err) != 0) {
        fprintf(stderr, "selftest FAILED: %s\n", err);
        return 1;
    }
    printf("kr_selftest: ok (RFC 8439 vector + roundtrip via AF_ALG)\n");

    static const char blob[] = "libkeyringer stash roundtrip payload";
    kr_opts o = { 0 };

    if (kr_stash(blob, sizeof(blob) - 1, &o, err) != 0) {
        fprintf(stderr, "kr_stash FAILED: %s\n", err);
        return 1;
    }
    printf("kr_stash: ok (%zu bytes stashed)\n", sizeof(blob) - 1);

    void *img = NULL;
    size_t n = 0;

    if (kr_load_revoke(&o, &img, &n, err) != 0) {
        fprintf(stderr, "kr_load_revoke FAILED: %s\n", err);
        return 1;
    }
    if (n != sizeof(blob) - 1 || memcmp(img, blob, n) != 0) {
        fprintf(stderr, "kr_load_revoke MISMATCH (%zu bytes)\n", n);
        free(img);
        return 1;
    }
    free(img);
    printf("kr_load_revoke: ok (%zu bytes verified, keys revoked)\n", n);
    printf("libkeyringer consumer: ALL OK\n");
    return 0;
}
