#include "check.h"
#include "maze.h"
#include "suites.h"

static maze_kdf kdf_with(uint8_t salt_byte)
{
    maze_kdf kdf;
    memset(kdf.salt, salt_byte, sizeof kdf.salt);
    kdf.opslimit = 1;
    kdf.memlimit = MAZE_KDF_MEM_MIN;
    return kdf;
}

static const char *const LAYER1[] = {"admin123", "letmein"};
static const char *const LAYER2[] = {"root!2024", "changeme_now"};
static const char *const REAL = "correct horse battery";

static void add(maze_engine *engine, uint32_t layer, const char *pw)
{
    maze_kdf kdf = kdf_with(1);
    uint8_t h[MAZE_HASH_BYTES];
    CHECK(maze_kdf_hash(&kdf, pw, strlen(pw), h) == MAZE_OK);
    CHECK(maze_engine_add_decoy(engine, layer, h) == MAZE_OK);
}

/* layer_count layers; decoy layers 1 and 2 get the lists above, any further
 * decoy layer L gets the single decoy "decoyL". */
static maze_engine *make_engine(uint32_t layer_count)
{
    maze_kdf decoy = kdf_with(1), real = kdf_with(2);
    uint8_t real_hash[MAZE_HASH_BYTES];
    CHECK(maze_kdf_hash(&real, REAL, strlen(REAL), real_hash) == MAZE_OK);
    maze_engine *engine = maze_engine_new(layer_count, &decoy, &real, real_hash);
    CHECK(engine != NULL);
    for (uint32_t layer = 1; layer < layer_count; layer++) {
        if (layer == 1) {
            add(engine, 1, LAYER1[0]);
            add(engine, 1, LAYER1[1]);
        } else if (layer == 2) {
            add(engine, 2, LAYER2[0]);
            add(engine, 2, LAYER2[1]);
        } else {
            char name[16];
            snprintf(name, sizeof name, "decoy%u", (unsigned)layer);
            add(engine, layer, name);
        }
    }
    return engine;
}

static maze_result guess(const maze_engine *engine, maze_session *s, const char *pw)
{
    maze_result r;
    CHECK(maze_login(engine, s, pw, strlen(pw), &r) == MAZE_OK);
    return r;
}

static void test_full_flow(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);

    maze_result r = guess(engine, &s, "letmein");
    CHECK(r.outcome == MAZE_DECOY_FOUND);
    CHECK(r.layer_before == 1 && r.layer_after == 2 && s.layer == 2);
    CHECK(s.cleared_mask == (1u << 1));

    r = guess(engine, &s, "root!2024");
    CHECK(r.outcome == MAZE_DECOY_FOUND);
    CHECK(r.layer_after == 3);
    CHECK(s.cleared_mask == ((1u << 1) | (1u << 2)));

    r = guess(engine, &s, REAL);
    CHECK(r.outcome == MAZE_REAL_SUCCESS);
    CHECK(r.decoy_layer == 0);
    maze_engine_free(engine);
}

static void test_wrong_password_stays(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);
    maze_result r = guess(engine, &s, "hunter2");
    CHECK(r.outcome == MAZE_WRONG && s.layer == 1 && s.cleared_mask == 0);
    guess(engine, &s, "admin123");
    r = guess(engine, &s, "hunter2");
    CHECK(r.outcome == MAZE_WRONG && s.layer == 2);
    r = guess(engine, &s, "");
    CHECK(r.outcome == MAZE_WRONG && s.layer == 2);
    maze_engine_free(engine);
}

static void test_no_layer_skipping(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);

    /* The real password and layer-2 decoys do nothing on layer 1. */
    CHECK(guess(engine, &s, REAL).outcome == MAZE_WRONG);
    CHECK(guess(engine, &s, "root!2024").outcome == MAZE_WRONG);
    CHECK(s.layer == 1);

    /* The real password and layer-1 decoys do nothing on layer 2. */
    guess(engine, &s, "admin123");
    CHECK(guess(engine, &s, REAL).outcome == MAZE_WRONG);
    CHECK(guess(engine, &s, "letmein").outcome == MAZE_WRONG);
    CHECK(s.layer == 2);

    /* A forged layer number is rejected, not clamped. */
    s.layer = 0;
    maze_result r;
    CHECK(maze_login(engine, &s, "x", 1, &r) == MAZE_ERR_ARG);
    s.layer = 4;
    CHECK(maze_login(engine, &s, "x", 1, &r) == MAZE_ERR_ARG);
    maze_engine_free(engine);
}

static void test_final_layer_rejects_decoys(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);
    guess(engine, &s, "admin123");
    guess(engine, &s, "changeme_now");

    maze_result r = guess(engine, &s, "admin123");
    CHECK(r.outcome == MAZE_WRONG && r.decoy_layer == 1 && s.layer == 3);
    r = guess(engine, &s, "changeme_now");
    CHECK(r.outcome == MAZE_WRONG && r.decoy_layer == 2 && s.layer == 3);
    r = guess(engine, &s, "nothing");
    CHECK(r.outcome == MAZE_WRONG && r.decoy_layer == 0);
    /* Near misses of the real password. */
    CHECK(guess(engine, &s, "correct horse battery ").outcome == MAZE_WRONG);
    CHECK(guess(engine, &s, "correct horse batter").outcome == MAZE_WRONG);
    CHECK(guess(engine, &s, REAL).outcome == MAZE_REAL_SUCCESS);
    maze_engine_free(engine);
}

static void test_configurable_layer_count(void)
{
    maze_engine *engine = make_engine(5);
    maze_session s;
    maze_session_init(&s);
    CHECK(maze_engine_layer_count(engine) == 5);
    guess(engine, &s, "admin123");
    guess(engine, &s, "root!2024");
    CHECK(guess(engine, &s, REAL).outcome == MAZE_WRONG); /* layer 3 is a decoy layer */
    CHECK(guess(engine, &s, "decoy3").layer_after == 4);
    CHECK(guess(engine, &s, "decoy4").layer_after == 5);
    maze_result r = guess(engine, &s, "decoy3");
    CHECK(r.outcome == MAZE_WRONG && r.decoy_layer == 3);
    CHECK(guess(engine, &s, REAL).outcome == MAZE_REAL_SUCCESS);
    maze_engine_free(engine);

    /* A single layer is just the final layer. */
    engine = make_engine(1);
    maze_session_init(&s);
    CHECK(guess(engine, &s, REAL).outcome == MAZE_REAL_SUCCESS);
    maze_engine_free(engine);
}

static void test_routing_rules(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);

    /* Layer 2: a wrong guess sends the session back to layer 1. */
    CHECK(maze_engine_set_route(engine, 2, 3, 1) == MAZE_OK);
    guess(engine, &s, "admin123");
    CHECK(guess(engine, &s, "nope").layer_after == 1);

    /* Layer 1: a decoy match loops back to layer 1. */
    CHECK(maze_engine_set_route(engine, 1, 1, 1) == MAZE_OK);
    maze_result r = guess(engine, &s, "letmein");
    CHECK(r.outcome == MAZE_DECOY_FOUND && r.layer_after == 1);

    /* Final layer: a wrong guess restarts the maze. */
    CHECK(maze_engine_set_route(engine, 1, 2, 1) == MAZE_OK);
    CHECK(maze_engine_set_route(engine, 3, 3, 1) == MAZE_OK);
    guess(engine, &s, "letmein");
    guess(engine, &s, "root!2024");
    CHECK(s.layer == 3);
    CHECK(guess(engine, &s, "nope").layer_after == 1);

    CHECK(maze_engine_set_route(engine, 0, 1, 1) == MAZE_ERR_ARG);
    CHECK(maze_engine_set_route(engine, 4, 1, 1) == MAZE_ERR_ARG);
    CHECK(maze_engine_set_route(engine, 1, 4, 1) == MAZE_ERR_ARG);
    CHECK(maze_engine_set_route(engine, 1, 2, 0) == MAZE_ERR_ARG);
    maze_engine_free(engine);
}

static void test_engine_rejects_bad_setup(void)
{
    maze_kdf ok = kdf_with(1), bad = kdf_with(1);
    uint8_t h[MAZE_HASH_BYTES] = {0};
    bad.opslimit = 0;

    CHECK(maze_engine_new(0, &ok, &ok, h) == NULL);
    CHECK(maze_engine_new(MAZE_MAX_LAYERS + 1, &ok, &ok, h) == NULL);
    CHECK(maze_engine_new(3, &bad, &ok, h) == NULL);
    CHECK(maze_engine_new(3, &ok, &bad, h) == NULL);
    CHECK(maze_engine_new(3, &ok, &ok, NULL) == NULL);

    maze_engine *engine = maze_engine_new(3, &ok, &ok, h);
    CHECK(engine != NULL);
    CHECK(maze_engine_add_decoy(engine, 0, h) == MAZE_ERR_ARG);
    CHECK(maze_engine_add_decoy(engine, 3, h) == MAZE_ERR_ARG); /* final layer */
    for (int i = 0; i < MAZE_MAX_DECOYS_PER_LAYER; i++)
        CHECK(maze_engine_add_decoy(engine, 1, h) == MAZE_OK);
    CHECK(maze_engine_add_decoy(engine, 1, h) == MAZE_ERR_ARG);

    maze_session s;
    maze_result r;
    maze_session_init(&s);
    CHECK(maze_login(NULL, &s, "x", 1, &r) == MAZE_ERR_ARG);
    CHECK(maze_login(engine, NULL, "x", 1, &r) == MAZE_ERR_ARG);
    CHECK(maze_login(engine, &s, "x", 1, NULL) == MAZE_ERR_ARG);
    CHECK(maze_login(engine, &s, "x", MAZE_MAX_PASSWORD_BYTES + 1, &r) == MAZE_ERR_ARG);
    CHECK(s.layer == 1);
    maze_engine_free(engine);
    maze_engine_free(NULL);
}

static maze_result exit_with(const maze_engine *engine, maze_session *s,
                             const char *a1, const char *a2)
{
    const char *answers[] = {a1, a2};
    size_t lens[] = {strlen(a1), strlen(a2)};
    maze_result r;
    CHECK(maze_exit(engine, s, answers, lens, s->layer - 1, &r) == MAZE_OK);
    return r;
}

static void test_exit_flow(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);
    maze_result r;

    CHECK(maze_exit(engine, &s, NULL, NULL, 0, &r) == MAZE_OK);
    CHECK(r.outcome == MAZE_EXIT_UNAVAILABLE && s.layer == 1);

    guess(engine, &s, "letmein");
    /* Another decoy of the same layer is not the one this session used. */
    CHECK(exit_with(engine, &s, "admin123", "").outcome == MAZE_EXIT_DENIED);
    CHECK(s.layer == 2);
    CHECK(exit_with(engine, &s, "letmein", "").outcome == MAZE_EXIT_GRANTED);
    CHECK(s.layer == 1 && s.cleared_mask == 0);

    guess(engine, &s, "admin123");
    guess(engine, &s, "changeme_now");
    CHECK(exit_with(engine, &s, "admin123", "root!2024").outcome == MAZE_EXIT_DENIED);
    CHECK(exit_with(engine, &s, "changeme_now", "admin123").outcome == MAZE_EXIT_DENIED);
    CHECK(s.layer == 3);
    r = exit_with(engine, &s, "admin123", "changeme_now");
    CHECK(r.outcome == MAZE_EXIT_GRANTED && r.layer_before == 3 && s.layer == 1);

    /* The answer count must match the layer. */
    guess(engine, &s, "admin123");
    const char *one[] = {"admin123"};
    size_t one_len[] = {8};
    CHECK(maze_exit(engine, &s, one, one_len, 0, &r) == MAZE_ERR_ARG);
    CHECK(maze_exit(engine, &s, one, one_len, 2, &r) == MAZE_ERR_ARG);
    CHECK(maze_exit(engine, &s, NULL, NULL, 1, &r) == MAZE_ERR_ARG);
    maze_engine_free(engine);
}

static void test_exit_needs_cleared_layers(void)
{
    /* With a custom route a session can reach layer 3 without clearing
     * layer 2; there is then nothing that could confirm layer 2. */
    maze_engine *engine = make_engine(3);
    CHECK(maze_engine_set_route(engine, 1, 3, 1) == MAZE_OK);
    maze_session s;
    maze_session_init(&s);
    guess(engine, &s, "letmein");
    CHECK(s.layer == 3);
    CHECK(exit_with(engine, &s, "letmein", "").outcome == MAZE_EXIT_DENIED);
    CHECK(exit_with(engine, &s, "letmein", "\0").outcome == MAZE_EXIT_DENIED);
    maze_engine_free(engine);
}

static void test_real_password_is_flagged_for_redaction(void)
{
    maze_engine *engine = make_engine(3);
    maze_session s;
    maze_session_init(&s);

    maze_result r = guess(engine, &s, REAL); /* layer 1: wrong, but flagged */
    CHECK(r.outcome == MAZE_WRONG && r.real_mask == 1);
    CHECK(guess(engine, &s, "nope").real_mask == 0);
    guess(engine, &s, "letmein");
    guess(engine, &s, "root!2024");
    r = exit_with(engine, &s, REAL, "root!2024");
    CHECK(r.outcome == MAZE_EXIT_DENIED && r.real_mask == 1);
    r = exit_with(engine, &s, "letmein", REAL);
    CHECK(r.real_mask == 2);
    CHECK(guess(engine, &s, REAL).real_mask == 1);
    maze_engine_free(engine);
}

static void test_abi_sizes(void)
{
    CHECK(maze_sizeof_kdf() == sizeof(maze_kdf));
    CHECK(maze_sizeof_session() == sizeof(maze_session));
    CHECK(maze_sizeof_result() == sizeof(maze_result));
}

void run_engine_tests(void)
{
    RUN(test_full_flow);
    RUN(test_wrong_password_stays);
    RUN(test_no_layer_skipping);
    RUN(test_final_layer_rejects_decoys);
    RUN(test_configurable_layer_count);
    RUN(test_routing_rules);
    RUN(test_engine_rejects_bad_setup);
    RUN(test_exit_flow);
    RUN(test_exit_needs_cleared_layers);
    RUN(test_real_password_is_flagged_for_redaction);
    RUN(test_abi_sizes);
}
