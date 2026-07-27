/* Smoke test for OHOS cross-compile: links against the static Botan
 * lib and exercises the SHA-3 hash via the C FFI. Exits 0 on success.
 * Built and run inside ghcr.io/hqzing/dockerharmony:latest.
 *
 * Uses only the C FFI surface (botan/ffi.h) — the C++ class headers
 * (botan/hash.h, botan/aead.h) require a C++ compiler. The C FFI for
 * AEAD uses botan_cipher_* (not botan_aead_*, which doesn't exist);
 * for a minimal smoke test, hashing is enough to confirm the static
 * lib links and runs on the target.
 *
 * Build:
 *   $NDK/llvm/bin/aarch64-unknown-linux-ohos-clang \
 *     -O2 -I$PREFIX/ohos-aarch64/include/botan-3 \
 *     ci/ohos-smoke.c \
 *     $PREFIX/ohos-aarch64/lib/libbotan-3.a \
 *     -lc++ -lc++abi -lpthread -ldl \
 *     -o ci/ohos-smoke
 *
 * Run (in dockerharmony):
 *   LD_LIBRARY_PATH=. ./ci/ohos-smoke
 */

#include <botan/ffi.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    /* FFI init: ensure the linked lib's API version is compatible. */
    botan_rng_t rng = NULL;
    if (botan_rng_init(&rng, "system") != 0) {
        printf("FAIL: botan_rng_init\n");
        return 1;
    }

    /* SHA-3(256) hash round-trip. */
    botan_hash_t h = NULL;
    if (botan_hash_init(&h, "SHA-3(256)", 0) != 0) {
        printf("FAIL: botan_hash_init SHA-3(256)\n");
        botan_rng_destroy(rng);
        return 1;
    }

    const unsigned char in[] = "hello, ohos";
    size_t in_len = sizeof(in) - 1;
    if (botan_hash_update(h, in, in_len) != 0) {
        printf("FAIL: botan_hash_update\n");
        botan_hash_destroy(h);
        botan_rng_destroy(rng);
        return 1;
    }

    unsigned char out[32] = {0};
    if (botan_hash_final(h, out) != 0) {
        printf("FAIL: botan_hash_final\n");
        botan_hash_destroy(h);
        botan_rng_destroy(rng);
        return 1;
    }

    /* Print the digest so the verification log shows it (and so the
     * pinned-value check after the first successful run can be added
     * here in a follow-up). */
    printf("OK: SHA3-256(\"hello, ohos\") = ");
    for (size_t i = 0; i < sizeof(out); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    /* Confirm RNG also works (exercises more than just hash code path). */
    unsigned char rand_bytes[16] = {0};
    if (botan_rng_get(rng, rand_bytes, sizeof(rand_bytes)) != 0) {
        printf("FAIL: botan_rng_get\n");
        botan_hash_destroy(h);
        botan_rng_destroy(rng);
        return 1;
    }

    printf("OK: RNG produced 16 random bytes\n");
    botan_hash_destroy(h);
    botan_rng_destroy(rng);
    printf("OHOS smoke test: OK\n");
    return 0;
}
