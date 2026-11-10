# libmaze build. Targets:
#   make          build build/libmaze.so
#   make test     build and run the C unit tests
#   make asan     run the tests under AddressSanitizer + UBSan
#   make clean

CC      ?= cc
BUILD   ?= build

WARN    = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
          -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Werror
HARDEN  = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-strict-overflow \
          -fno-delete-null-pointer-checks
# CFLAGS is for the user (optimisation, sanitizers); the required flags below
# are always added, even when CFLAGS is set on the command line.
CFLAGS  ?= -O2 -g
MAZE_CFLAGS = $(CFLAGS) -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(HARDEN) -Iinclude
LDFLAGS += -Wl,-z,relro,-z,now -Wl,-z,noexecstack

SRCS    = $(wildcard src/*.c)
TESTS   = $(wildcard tests/*.c)

LIB     = $(BUILD)/libmaze.so
TESTBIN = $(BUILD)/test_maze

.PHONY: all test asan clean

all: $(LIB)

$(LIB): $(SRCS) include/maze.h | $(BUILD)
	$(CC) $(MAZE_CFLAGS) -fPIC -shared -fvisibility=default $(SRCS) -o $@ $(LDFLAGS)

$(TESTBIN): $(SRCS) $(TESTS) include/maze.h tests/check.h | $(BUILD)
	$(CC) $(MAZE_CFLAGS) -fPIE $(SRCS) $(TESTS) -o $@ -pie $(LDFLAGS)

test: $(TESTBIN)
	./$(TESTBIN)

asan:
	$(MAKE) BUILD=$(BUILD)/asan \
	    CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
	    test

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)
