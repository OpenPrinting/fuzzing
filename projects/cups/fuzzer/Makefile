FUZZ_SRCS := $(filter-out fuzz_ppd.c, $(wildcard fuzz_*.c))
TARGETS := $(basename $(FUZZ_SRCS))

# For local build
# export CC=clang
# export CXX=clang++
# LIB_FUZZING_ENGINE=/root/libFuzzer.a

BUILDTOP=./../

INCLUDE=\
	-I$(BUILDTOP)\
	-I$(BUILDTOP)/cups/

# `ALL_CFLAGS` are copied from the make process.
ALL_CFLAGS=\
	-D_CUPS_SOURCE -D_FORTIFY_SOURCE=3 -D_REENTRANT  -D_LARGEFILE_SOURCE\
	-D_LARGEFILE64_SOURCE -D_THREAD_SAFE -D_REENTRANT\
	-Wall -Wunused -Wno-char-subscripts -Wno-deprecated-declarations\
	-Wno-format-y2k -Wno-switch -Wno-unused-result -g

LIBRARY=\
	-L$(BUILDTOP)/cups/

# Using static libraries is important for OSS-Fuzz infrastructure.
# `LIB_FUZZING_ENGINE` can be used with the AFL driver.

ALL_LDFLAGS=\
	$(LIBRARY)\
	-lcups -lcupsimage\
	-l:libavahi-common.a -l:libavahi-client.a -l:libdbus-1.a\
	-lssl -lcrypto -lz -lpthread -lcrypt -lsystemd\
	$(LIB_FUZZING_ENGINE)
# -fsanitize=address # only for debugging

.PHONY: $(TARGETS)

all: $(TARGETS)

# Using `CXX` as linker
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements

$(TARGETS):
	$(CC) $(CFLAGS) $(ALL_CFLAGS) $(INCLUDE) -c $@.c
	$(CXX) $(CFLAGS) $(ALL_CFLAGS) $(INCLUDE) -c -o fuzz_helpers.o fuzz_helpers.cpp
	$(CXX) $(CFLAGS) -o $@ $@.o fuzz_helpers.o $(ALL_LDFLAGS)

oss_fuzzers:
	cp $(TARGETS) $(OUT)

clean:
	rm $(TARGETS) *.o
