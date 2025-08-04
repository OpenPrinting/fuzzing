FUZZ_SRCS := $(wildcard fuzz_*.c)
TARGETS := $(basename $(FUZZ_SRCS))

export CC=clang
export CXX=clang++

ifeq ($(FUZZING_ENGINE), afl)
    export CC=afl-clang-fast
    export CXX=afl-clang-fast++
endif

mkdir -p '$(OUT)/lib/'
cp /usr/lib/x86_64-linux-gnu/liblcms2.so.2 '$(OUT)/lib/'
cp /usr/lib/x86_64-linux-gnu/libpoppler.so.134 '$(OUT)/lib/'

INCDIR=-I./../ -I./../cupsfilters/
LIBDIR=-L./../cupsfilters/ -L./../ -L./../.libs
BUILD_FLAGS=-g -O0
LINK_FLAGS=-g -O0 -l:libcupsfilters.a -l:libcups.a -l:libgnutls.a -l:libtasn1.a -l:libhogweed.a -l:libgmp.a -l:libnettle.a -l:libidn2.a -l:libunistring.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -l:libcap.a -lz -l:libglib-2.0.a -l:libqpdf.a -l:libjpeg.a -l:libp11-kit.so -l:libgssapi_krb5.so.2 -lsystemd -lpthread -l:liblcms2.so -l:libpoppler.so

All: $(TARGETS)

fuzz_dither:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_dither.o fuzz_dither.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o fuzz_dither fuzz_dither.o $(LINK_FLAGS) -Wl,-rpath,'$$ORIGIN/lib'

oss_fuzzers:
	cp $(TARGETS) $(OUT)
# for loading missing shared libs
	mkdir -p '$(OUT)/lib/'
	cp /usr/lib/x86_64-linux-gnu/liblcms2.so.2 '$(OUT)/lib/'
	cp /usr/lib/x86_64-linux-gnu/libpoppler.so.134 '$(OUT)/lib/'
# chrpath -r '$$ORIGIN/lib' $$OUT/$$TARGETS # move to oss_fuzz_build.sh

clean:
	rm -f $(TARGETS) *.o $(TARGETS)