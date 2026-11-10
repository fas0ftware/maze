#include "check.h"
#include "maze.h"
#include "suites.h"

/* Cheap parameters: the tests check behaviour, not strength. */
static maze_kdf test_kdf(uint8_t salt_byte)
{
    maze_kdf kdf;
    memset(kdf.salt, salt_byte, sizeof kdf.salt);
    kdf.opslimit = 1;
    kdf.memlimit = MAZE_KDF_MEM_MIN;
    return kdf;
}

static void hash_of(const maze_kdf *kdf, const char *pw, uint8_t out[MAZE_HASH_BYTES])
{
    CHECK(maze_kdf_hash(kdf, pw, strlen(pw), out) == MAZE_OK);
}

static void test_hash_is_deterministic(void)
{
    maze_kdf kdf = test_kdf(7);
    uint8_t a[MAZE_HASH_BYTES], b[MAZE_HASH_BYTES];
    hash_of(&kdf, "admin123", a);
    hash_of(&kdf, "admin123", b);
    CHECK(maze_hash_equal(a, b) == 1);
}

static void test_hash_depends_on_password_and_salt(void)
{
    maze_kdf kdf = test_kdf(7), other = test_kdf(8);
    uint8_t a[MAZE_HASH_BYTES], b[MAZE_HASH_BYTES], c[MAZE_HASH_BYTES];
    hash_of(&kdf, "admin123", a);
    hash_of(&kdf, "admin124", b);
    hash_of(&other, "admin123", c);
    CHECK(maze_hash_equal(a, b) == 0);
    CHECK(maze_hash_equal(a, c) == 0);
}

static void test_hash_uses_length_not_nul(void)
{
    maze_kdf kdf = test_kdf(1);
    uint8_t a[MAZE_HASH_BYTES], b[MAZE_HASH_BYTES];
    CHECK(maze_kdf_hash(&kdf, "ab\0cd", 5, a) == MAZE_OK);
    CHECK(maze_kdf_hash(&kdf, "ab", 2, b) == MAZE_OK);
    CHECK(maze_hash_equal(a, b) == 0);
}

static void test_hash_empty_password(void)
{
    maze_kdf kdf = test_kdf(1);
    uint8_t a[MAZE_HASH_BYTES], b[MAZE_HASH_BYTES];
    CHECK(maze_kdf_hash(&kdf, NULL, 0, a) == MAZE_OK);
    CHECK(maze_kdf_hash(&kdf, "", 0, b) == MAZE_OK);
    CHECK(maze_hash_equal(a, b) == 1);
}

static void test_hash_rejects_bad_arguments(void)
{
    maze_kdf kdf = test_kdf(1);
    uint8_t out[MAZE_HASH_BYTES];
    static char big[MAZE_MAX_PASSWORD_BYTES + 1];

    CHECK(maze_kdf_hash(NULL, "x", 1, out) == MAZE_ERR_ARG);
    CHECK(maze_kdf_hash(&kdf, "x", 1, NULL) == MAZE_ERR_ARG);
    CHECK(maze_kdf_hash(&kdf, NULL, 1, out) == MAZE_ERR_ARG);
    CHECK(maze_kdf_hash(&kdf, big, sizeof big, out) == MAZE_ERR_ARG);
    CHECK(maze_kdf_hash(&kdf, big, MAZE_MAX_PASSWORD_BYTES, out) == MAZE_OK);

    kdf.opslimit = 0;
    CHECK(maze_kdf_valid(&kdf) == 0);
    CHECK(maze_kdf_hash(&kdf, "x", 1, out) == MAZE_ERR_ARG);
    kdf.opslimit = MAZE_KDF_OPS_MAX + 1;
    CHECK(maze_kdf_valid(&kdf) == 0);
    kdf = test_kdf(1);
    kdf.memlimit = MAZE_KDF_MEM_MIN - 1;
    CHECK(maze_kdf_valid(&kdf) == 0);
    kdf.memlimit = MAZE_KDF_MEM_MAX + 1;
    CHECK(maze_kdf_valid(&kdf) == 0);
}

static void test_random_salt_differs(void)
{
    maze_kdf a = test_kdf(0), b = test_kdf(0);
    maze_kdf_random_salt(&a);
    maze_kdf_random_salt(&b);
    CHECK(memcmp(a.salt, b.salt, MAZE_SALT_BYTES) != 0);
}

static void test_find_scans_list(void)
{
    maze_kdf kdf = test_kdf(3);
    const char *words[] = {"letmein", "P@ssw0rd", "Winter2024!"};
    uint8_t list[3][MAZE_HASH_BYTES], cand[MAZE_HASH_BYTES];
    size_t index = 99;

    for (size_t i = 0; i < 3; i++)
        hash_of(&kdf, words[i], list[i]);

    hash_of(&kdf, "P@ssw0rd", cand);
    CHECK(maze_hash_find(cand, (const uint8_t (*)[MAZE_HASH_BYTES])list, 3, &index) == 1);
    CHECK(index == 1);

    hash_of(&kdf, "Winter2024!", cand);
    CHECK(maze_hash_find(cand, (const uint8_t (*)[MAZE_HASH_BYTES])list, 3, &index) == 1);
    CHECK(index == 2);

    hash_of(&kdf, "nope", cand);
    CHECK(maze_hash_find(cand, (const uint8_t (*)[MAZE_HASH_BYTES])list, 3, &index) == 0);
    CHECK(index == 3);

    CHECK(maze_hash_find(cand, NULL, 0, NULL) == 0);
}

void run_hash_tests(void)
{
    RUN(test_hash_is_deterministic);
    RUN(test_hash_depends_on_password_and_salt);
    RUN(test_hash_uses_length_not_nul);
    RUN(test_hash_empty_password);
    RUN(test_hash_rejects_bad_arguments);
    RUN(test_random_salt_differs);
    RUN(test_find_scans_list);
}
