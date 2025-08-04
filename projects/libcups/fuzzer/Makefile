FUZZ_SRCS := $(wildcard fuzz*.c)
TARGETS := $(basename $(FUZZ_SRCS))

CC=clang
CXX=clang++

INCDIR=-I./../ -I./../cups/ -I../pdfio
LIBDIR=-L./../cups/ -L./../pdfio
BUILD_FLAGS=-D_CUPS_SOURCE -D_THREAD_SAFE -D_REENTRANT -D_REENTRANT -DDBUS_API_SUBJECT_TO_CHANGE -D_FORTIFY_SOURCE=3 -D__USE_MISC -D_GNU_SOURCE -fPIC -g -Os -Wall -Wunused -Wno-char-subscripts -Wno-deprecated-declarations -Wno-format-y2k -Wno-switch -Wno-unused-result
LINK_FLAGS=-fuse-ld=lld -fPIE -pie -Wl,-z,relro,-z,now -g -Os -lz -lpthread -l:libcups3.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -lssl -lcrypto -lm -lsystemd

All: $(TARGETS)

$(TARGETS):
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o $@.o $@.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) $(LINK_FLAGS) -o $@ $@.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)

clean:
	rm -f $(TARGETS) *.o $(TARGETS)