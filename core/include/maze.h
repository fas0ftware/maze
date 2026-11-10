/*
 * libmaze: core engine of the Maze deception service.
 *
 * The public API is plain C with no global state, so it can be called from
 * C programs or from Python through ctypes.
 */
#ifndef MAZE_H
#define MAZE_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAZE_VERSION_MAJOR 0
#define MAZE_VERSION_MINOR 1
#define MAZE_VERSION_PATCH 0

/* Version string of the linked library, for example "0.1.0". */
const char *maze_version(void);

#ifdef __cplusplus
}
#endif

#endif /* MAZE_H */
