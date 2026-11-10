#include "maze.h"

#define MAZE_STR_(x) #x
#define MAZE_STR(x) MAZE_STR_(x)

const char *maze_version(void)
{
    return MAZE_STR(MAZE_VERSION_MAJOR) "." MAZE_STR(MAZE_VERSION_MINOR) "."
           MAZE_STR(MAZE_VERSION_PATCH);
}
