/* Minimal test helpers: no framework, no dependencies. */
#ifndef MAZE_CHECK_H
#define MAZE_CHECK_H

#include <stdio.h>
#include <string.h>

extern int check_failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                  \
            check_failures++;                                                \
        }                                                                    \
    } while (0)

#define CHECK_STR_EQ(a, b) CHECK(strcmp((a), (b)) == 0)

#define RUN(test)                                \
    do {                                         \
        int before_ = check_failures;            \
        test();                                  \
        printf("%s %s\n",                        \
               check_failures == before_ ? "PASS" : "FAIL", #test); \
    } while (0)

#endif /* MAZE_CHECK_H */
