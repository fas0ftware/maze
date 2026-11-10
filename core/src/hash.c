/* Argon2id hashing and constant-time hash comparison (libsodium). */
#include <sodium.h>

#include "maze.h"

_Static_assert(MAZE_SALT_BYTES == crypto_pwhash_argon2id_SALTBYTES,
               "salt size must match libsodium");
_Static_assert(MAZE_HASH_BYTES >= crypto_pwhash_argon2id_BYTES_MIN,
               "hash too short for Argon2id");

int maze_init(void)
{
    /* 0 = initialised now, 1 = already initialised, -1 = failure. */
    return sodium_init() < 0 ? MAZE_ERR_CRYPTO : MAZE_OK;
}

int maze_kdf_valid(const maze_kdf *kdf)
{
    return kdf != NULL && kdf->opslimit >= MAZE_KDF_OPS_MIN &&
           kdf->opslimit <= MAZE_KDF_OPS_MAX &&
           kdf->memlimit >= MAZE_KDF_MEM_MIN &&
           kdf->memlimit <= MAZE_KDF_MEM_MAX;
}

void maze_kdf_random_salt(maze_kdf *kdf)
{
    randombytes_buf(kdf->salt, sizeof kdf->salt);
}

int maze_kdf_hash(const maze_kdf *kdf, const char *password, size_t len,
                  uint8_t out[MAZE_HASH_BYTES])
{
    if (!maze_kdf_valid(kdf) || out == NULL || (password == NULL && len > 0) ||
        len > MAZE_MAX_PASSWORD_BYTES)
        return MAZE_ERR_ARG;
    if (password == NULL)
        password = "";
    if (crypto_pwhash(out, MAZE_HASH_BYTES, password, len, kdf->salt,
                      kdf->opslimit, kdf->memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return MAZE_ERR_CRYPTO;
    return MAZE_OK;
}

int maze_hash_equal(const uint8_t a[MAZE_HASH_BYTES],
                    const uint8_t b[MAZE_HASH_BYTES])
{
    /* sodium_memcmp is constant-time and returns 0 (equal) or -1. */
    return sodium_memcmp(a, b, MAZE_HASH_BYTES) + 1;
}

int maze_hash_find(const uint8_t candidate[MAZE_HASH_BYTES],
                   const uint8_t (*list)[MAZE_HASH_BYTES], size_t n,
                   size_t *index)
{
    size_t found = 0;
    size_t where = n;

    for (size_t i = 0; i < n; i++) {
        /* eq is 1 or 0; mask is all ones or all zeros. No branch on it. */
        size_t eq = (size_t)maze_hash_equal(candidate, list[i]);
        size_t mask = (size_t)0 - eq;
        where = (where & ~mask) | (i & mask);
        found |= eq;
    }
    if (index != NULL)
        *index = where;
    return (int)found;
}
