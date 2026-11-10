/* Layer engine: decoy layers, routing rules and the constant-time final layer. */
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "maze.h"

_Static_assert(MAZE_MAX_LAYERS < 32, "cleared_mask must hold every layer");

typedef struct {
    uint8_t hashes[MAZE_MAX_DECOYS_PER_LAYER][MAZE_HASH_BYTES];
    size_t count;
    uint32_t on_match;
    uint32_t on_wrong;
} layer_def;

struct maze_engine {
    uint32_t layer_count;
    maze_kdf decoy_kdf;
    maze_kdf real_kdf;
    uint8_t real_hash[MAZE_HASH_BYTES];
    layer_def layers[MAZE_MAX_LAYERS + 1]; /* index 0 unused */
};

static int valid_layer(const maze_engine *engine, uint32_t layer)
{
    return layer >= 1 && layer <= engine->layer_count;
}

maze_engine *maze_engine_new(uint32_t layer_count, const maze_kdf *decoy_kdf,
                             const maze_kdf *real_kdf,
                             const uint8_t real_hash[MAZE_HASH_BYTES])
{
    if (layer_count < 1 || layer_count > MAZE_MAX_LAYERS ||
        !maze_kdf_valid(decoy_kdf) || !maze_kdf_valid(real_kdf) ||
        real_hash == NULL)
        return NULL;

    maze_engine *engine = calloc(1, sizeof *engine);
    if (engine == NULL)
        return NULL;
    engine->layer_count = layer_count;
    engine->decoy_kdf = *decoy_kdf;
    engine->real_kdf = *real_kdf;
    memcpy(engine->real_hash, real_hash, MAZE_HASH_BYTES);
    for (uint32_t layer = 1; layer <= layer_count; layer++) {
        engine->layers[layer].on_match = layer < layer_count ? layer + 1 : layer;
        engine->layers[layer].on_wrong = layer;
    }
    return engine;
}

void maze_engine_free(maze_engine *engine)
{
    if (engine == NULL)
        return;
    sodium_memzero(engine, sizeof *engine);
    free(engine);
}

int maze_engine_add_decoy(maze_engine *engine, uint32_t layer,
                          const uint8_t hash[MAZE_HASH_BYTES])
{
    if (engine == NULL || hash == NULL || layer < 1 ||
        layer >= engine->layer_count)
        return MAZE_ERR_ARG;
    layer_def *def = &engine->layers[layer];
    if (def->count >= MAZE_MAX_DECOYS_PER_LAYER)
        return MAZE_ERR_ARG;
    memcpy(def->hashes[def->count++], hash, MAZE_HASH_BYTES);
    return MAZE_OK;
}

int maze_engine_set_route(maze_engine *engine, uint32_t layer,
                          uint32_t on_match, uint32_t on_wrong)
{
    if (engine == NULL || !valid_layer(engine, layer) ||
        !valid_layer(engine, on_match) || !valid_layer(engine, on_wrong))
        return MAZE_ERR_ARG;
    engine->layers[layer].on_match = on_match;
    engine->layers[layer].on_wrong = on_wrong;
    return MAZE_OK;
}

uint32_t maze_engine_layer_count(const maze_engine *engine)
{
    return engine == NULL ? 0 : engine->layer_count;
}

void maze_session_init(maze_session *session)
{
    sodium_memzero(session, sizeof *session);
    session->layer = 1;
}

static const uint8_t (*decoy_list(const maze_engine *engine,
                                  uint32_t layer))[MAZE_HASH_BYTES]
{
    return (const uint8_t (*)[MAZE_HASH_BYTES])engine->layers[layer].hashes;
}

/* Hash a guess with both KDFs. Every login and every exit answer goes
 * through this, so all of them cost the same. */
static int hash_both(const maze_engine *engine, const char *password, size_t len,
                     uint8_t real_guess[MAZE_HASH_BYTES],
                     uint8_t decoy_guess[MAZE_HASH_BYTES], uint32_t *is_real)
{
    int rc = maze_kdf_hash(&engine->real_kdf, password, len, real_guess);
    if (rc == MAZE_OK)
        rc = maze_kdf_hash(&engine->decoy_kdf, password, len, decoy_guess);
    if (rc != MAZE_OK) {
        sodium_memzero(real_guess, MAZE_HASH_BYTES);
        sodium_memzero(decoy_guess, MAZE_HASH_BYTES);
        return rc;
    }
    *is_real = (uint32_t)maze_hash_equal(real_guess, engine->real_hash);
    sodium_memzero(real_guess, MAZE_HASH_BYTES);
    return MAZE_OK;
}

/* Final layer: compare with every decoy of every layer. The matched decoy
 * layer is selected with masks, not branches. */
static uint32_t match_any_decoy_layer(const maze_engine *engine,
                                      const uint8_t decoy_guess[MAZE_HASH_BYTES])
{
    uint32_t matched = 0;
    for (uint32_t layer = 1; layer < engine->layer_count; layer++) {
        uint32_t hit = (uint32_t)maze_hash_find(
            decoy_guess, decoy_list(engine, layer), engine->layers[layer].count,
            NULL);
        uint32_t mask = (uint32_t)0 - hit;
        matched = (matched & ~mask) | (layer & mask);
    }
    return matched;
}

int maze_login(const maze_engine *engine, maze_session *session,
               const char *password, size_t len, maze_result *result)
{
    if (engine == NULL || session == NULL || result == NULL ||
        !valid_layer(engine, session->layer))
        return MAZE_ERR_ARG;

    const uint32_t layer = session->layer;
    const layer_def *def = &engine->layers[layer];
    uint8_t real_guess[MAZE_HASH_BYTES], guess[MAZE_HASH_BYTES];
    uint32_t is_real = 0;
    int rc = hash_both(engine, password, len, real_guess, guess, &is_real);
    if (rc != MAZE_OK)
        return rc;

    memset(result, 0, sizeof *result);
    result->layer_before = layer;
    result->real_mask = is_real;

    if (layer == engine->layer_count) {
        /* A decoy on the final layer is just a wrong guess for the client. */
        result->decoy_layer = match_any_decoy_layer(engine, guess);
        if (is_real) {
            result->outcome = MAZE_REAL_SUCCESS;
        } else {
            result->outcome = MAZE_WRONG;
            session->layer = def->on_wrong;
        }
    } else if (maze_hash_find(guess, decoy_list(engine, layer), def->count,
                              NULL)) {
        /* Only this layer's list counts, so a decoy of another layer (or the
         * real password) cannot be used to skip ahead. */
        result->outcome = MAZE_DECOY_FOUND;
        result->decoy_layer = layer;
        memcpy(session->cleared[layer], guess, MAZE_HASH_BYTES);
        session->cleared_mask |= (uint32_t)1 << layer;
        session->layer = def->on_match;
    } else {
        result->outcome = MAZE_WRONG;
        session->layer = def->on_wrong;
    }
    sodium_memzero(guess, sizeof guess);
    result->layer_after = session->layer;
    return MAZE_OK;
}

int maze_exit(const maze_engine *engine, maze_session *session,
              const char *const *answers, const size_t *lens, size_t n,
              maze_result *result)
{
    if (engine == NULL || session == NULL || result == NULL ||
        !valid_layer(engine, session->layer) || n != session->layer - 1 ||
        (n > 0 && (answers == NULL || lens == NULL)))
        return MAZE_ERR_ARG;

    const uint32_t layer = session->layer;
    memset(result, 0, sizeof *result);
    result->layer_before = layer;
    result->layer_after = layer;
    if (layer == 1) {
        result->outcome = MAZE_EXIT_UNAVAILABLE;
        return MAZE_OK;
    }

    uint32_t all_match = 1;
    for (uint32_t i = 1; i < layer; i++) {
        uint8_t real_guess[MAZE_HASH_BYTES], guess[MAZE_HASH_BYTES];
        uint32_t is_real = 0;
        int rc = hash_both(engine, answers[i - 1], lens[i - 1], real_guess,
                           guess, &is_real);
        if (rc != MAZE_OK)
            return rc;
        uint32_t cleared = (session->cleared_mask >> i) & 1u;
        all_match &= cleared &
                     (uint32_t)maze_hash_equal(guess, session->cleared[i]);
        result->real_mask |= is_real << (i - 1);
        sodium_memzero(guess, sizeof guess);
    }

    if (all_match) {
        maze_session_init(session);
        result->outcome = MAZE_EXIT_GRANTED;
        result->layer_after = 1;
    } else {
        result->outcome = MAZE_EXIT_DENIED;
    }
    return MAZE_OK;
}

size_t maze_sizeof_kdf(void) { return sizeof(maze_kdf); }
size_t maze_sizeof_session(void) { return sizeof(maze_session); }
size_t maze_sizeof_result(void) { return sizeof(maze_result); }
