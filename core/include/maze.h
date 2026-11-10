/*
 * libmaze: core engine of the Maze deception service.
 *
 * The public API is plain C with no global state, so it can be called from
 * C programs or from Python through ctypes.
 */
#ifndef MAZE_H
#define MAZE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAZE_VERSION_MAJOR 0
#define MAZE_VERSION_MINOR 1
#define MAZE_VERSION_PATCH 0

/* Version string of the linked library, for example "0.1.0". */
const char *maze_version(void);

/* Status codes returned by every fallible function. */
enum maze_status {
    MAZE_OK = 0,
    MAZE_ERR_ARG = -1,    /* bad argument (NULL, out of range, too long) */
    MAZE_ERR_CRYPTO = -2, /* libsodium failed (for example out of memory) */
};

/* Initialise the library. Call once before anything else; safe to repeat. */
int maze_init(void);

/* ---- Password hashing (Argon2id via libsodium) -------------------------- */

#define MAZE_HASH_BYTES 32
#define MAZE_SALT_BYTES 16
/* Longest password the engine hashes; longer input is rejected. */
#define MAZE_MAX_PASSWORD_BYTES 4096

/* Accepted Argon2id cost range. Every guess costs one hash, so the upper
 * bounds keep a flood of guesses from exhausting CPU and memory. */
#define MAZE_KDF_OPS_MIN 1u
#define MAZE_KDF_OPS_MAX 10u
#define MAZE_KDF_MEM_MIN ((size_t)8 * 1024)
#define MAZE_KDF_MEM_MAX ((size_t)256 * 1024 * 1024)

typedef struct {
    uint8_t salt[MAZE_SALT_BYTES];
    uint32_t opslimit; /* Argon2 passes (t) */
    size_t memlimit;   /* bytes of memory (m) */
} maze_kdf;

/* 1 if the cost parameters are inside the accepted range, else 0. */
int maze_kdf_valid(const maze_kdf *kdf);

/* Fill kdf->salt with random bytes. */
void maze_kdf_random_salt(maze_kdf *kdf);

/* Argon2id hash of password[0..len) into out. The password may contain NUL
 * bytes; only len counts. */
int maze_kdf_hash(const maze_kdf *kdf, const char *password, size_t len,
                  uint8_t out[MAZE_HASH_BYTES]);

/* Constant-time comparison of two hashes: 1 if equal, else 0. */
int maze_hash_equal(const uint8_t a[MAZE_HASH_BYTES],
                    const uint8_t b[MAZE_HASH_BYTES]);

/* Compare candidate with every entry of list, always scanning the whole list
 * with no data-dependent branches. Returns 1 and stores the index of the
 * (last) match in *index if found, else returns 0 and stores n. index may be
 * NULL. */
int maze_hash_find(const uint8_t candidate[MAZE_HASH_BYTES],
                   const uint8_t (*list)[MAZE_HASH_BYTES], size_t n,
                   size_t *index);

#ifdef __cplusplus
}
#endif

#endif /* MAZE_H */
