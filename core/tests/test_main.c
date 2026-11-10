#include "check.h"
#include "maze.h"
#include "suites.h"

int check_failures = 0;

static void test_version(void)
{
    CHECK_STR_EQ(maze_version(), "0.1.0");
}

int main(void)
{
    if (maze_init() != MAZE_OK) {
        fprintf(stderr, "maze_init failed\n");
        return 1;
    }
    RUN(test_version);
    run_hash_tests();
    run_engine_tests();
    if (check_failures) {
        fprintf(stderr, "%d check(s) failed\n", check_failures);
        return 1;
    }
    puts("all C tests passed");
    return 0;
}
