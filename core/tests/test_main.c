#include "check.h"
#include "maze.h"

int check_failures = 0;

static void test_version(void)
{
    CHECK_STR_EQ(maze_version(), "0.1.0");
}

int main(void)
{
    RUN(test_version);
    if (check_failures) {
        fprintf(stderr, "%d check(s) failed\n", check_failures);
        return 1;
    }
    puts("all C tests passed");
    return 0;
}
