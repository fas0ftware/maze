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

/* ---- Layer engine ------------------------------------------------------- *
 *
 * Layers are numbered 1..layer_count. Layers 1..layer_count-1 are decoy
 * layers, each with its own list of decoy password hashes. The last layer is
 * the final layer: it accepts only the real password.
 *
 * All decoys share one KDF (one salt); the real password has its own KDF.
 * Every guess, on every layer, is hashed with both, so a guess always costs
 * exactly two Argon2id hashes. On the final layer the guess is compared in
 * constant time with the real hash and with every decoy of every layer, so
 * response time does not reveal whether the guess was the real password, a
 * decoy, or neither. On decoy layers the real hash is only used to tell the
 * caller that the real password must be redacted from the log.
 *
 * The engine is immutable once built and may be shared between threads. A
 * session is owned by the caller, who must serialise calls on one session.
 */

#define MAZE_MAX_LAYERS 16
#define MAZE_MAX_DECOYS_PER_LAYER 64

enum maze_outcome {
    MAZE_WRONG = 0,
    MAZE_DECOY_FOUND = 1,
    MAZE_REAL_SUCCESS = 2,
    MAZE_EXIT_GRANTED = 3,
    MAZE_EXIT_DENIED = 4,
    MAZE_EXIT_UNAVAILABLE = 5,
};

typedef struct maze_engine maze_engine; /* opaque */

typedef struct {
    uint32_t layer;        /* current layer, 1..layer_count */
    uint32_t cleared_mask; /* bit L set: layer L was cleared with a decoy */
    /* Hash of the decoy that cleared each layer (index = layer). Kept for
     * the exit flow; plaintext guesses are never stored. */
    uint8_t cleared[MAZE_MAX_LAYERS + 1][MAZE_HASH_BYTES];
} maze_session;

typedef struct {
    int outcome;           /* enum maze_outcome */
    uint32_t layer_before;
    uint32_t layer_after;
    /* For logging only, never shown to the client: on the final layer, the
     * decoy layer whose list the guess matched (0 if none). On a decoy layer,
     * the matched layer itself when the outcome is MAZE_DECOY_FOUND. */
    uint32_t decoy_layer;
    /* For log redaction only: bit 0 (login) or bit i-1 (exit answer for
     * layer i) is set when that input was exactly the real password. */
    uint32_t real_mask;
} maze_result;

/* New engine with layer_count layers (1..MAZE_MAX_LAYERS) and no decoys.
 * real_hash is the real password hashed with real_kdf. Default routes: a
 * decoy match moves to the next layer, a wrong guess stays. Returns NULL on
 * bad arguments or out of memory. */
maze_engine *maze_engine_new(uint32_t layer_count, const maze_kdf *decoy_kdf,
                             const maze_kdf *real_kdf,
                             const uint8_t real_hash[MAZE_HASH_BYTES]);
void maze_engine_free(maze_engine *engine);

/* Add a decoy hash (made with decoy_kdf) to a decoy layer. */
int maze_engine_add_decoy(maze_engine *engine, uint32_t layer,
                          const uint8_t hash[MAZE_HASH_BYTES]);

/* Routing rule of a layer: the layer a session moves to on a decoy match
 * (ignored on the final layer) and on a wrong guess. Targets are 1..count. */
int maze_engine_set_route(maze_engine *engine, uint32_t layer,
                          uint32_t on_match, uint32_t on_wrong);

uint32_t maze_engine_layer_count(const maze_engine *engine);

/* Start a session on layer 1 with nothing cleared. */
void maze_session_init(maze_session *session);

/* Evaluate one login guess on the session's current layer and move the
 * session according to the routing rule. The layer always comes from the
 * session, never from the client. */
int maze_login(const maze_engine *engine, maze_session *session,
               const char *password, size_t len, maze_result *result);

/* Fake exit (a stalling loop, not access control). The client must repeat
 * the decoy that cleared each layer below the current one: answers[i] and
 * lens[i] are the answer for layer i+1, and n must equal layer - 1. If every
 * answer matches, the session restarts on layer 1 (MAZE_EXIT_GRANTED); if not,
 * nothing changes (MAZE_EXIT_DENIED). On layer 1 there is nothing to confirm
 * (MAZE_EXIT_UNAVAILABLE). All answers are always hashed and compared. */
int maze_exit(const maze_engine *engine, maze_session *session,
              const char *const *answers, const size_t *lens, size_t n,
              maze_result *result);

/* sizeof of the public structs, so bindings (ctypes) can check their layout. */
size_t maze_sizeof_kdf(void);
size_t maze_sizeof_session(void);
size_t maze_sizeof_result(void);

#ifdef __cplusplus
}
#endif

#endif /* MAZE_H */
