TARGETS = \
	fuzz_texttopdf \
	# fuzz_texttopdf_2

export CC=clang
export CXX=clang++

ifeq ($(FUZZING_ENGINE), afl)
    export CC=afl-clang
    export CXX=afl-clang++
endif

ifeq ($(SANITIZER), introspector)
	export CC=clang
	export CXX=clang++
endif

INCDIR=-I./../ -I./../filter/
LIBDIR=-L./../filter/
BUILD_FLAGS=-g -O0
LINK_FLAGS=-g -O0 -l:libcups.a -l:libcupsfilters.a -l:libppd.a -l:libgnutls.a -l:libtasn1.a -l:libhogweed.a -l:libgmp.a -l:libnettle.a -l:libidn2.a -l:libunistring.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -l:libcap.a -lz -l:libglib-2.0.a -l:libp11-kit.so -l:libgssapi_krb5.so.2 -lsystemd -lpthread
# LINK_FLAGS=-g -O0 -Wl,-Bstatic -lcups -lppd -lcupsfilters -lgnutls -ltasn1 -lhogweed -lgmp -lnettle -l:libidn2.a -l:libunistring.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -l:libsystemd.a -l:libcap.a -lz -l:libglib-2.0.a -Wl,-Bdynamic -lp11-kit -l:libgssapi_krb5.so.2

All: $(TARGETS)

fuzz_texttopdf:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_texttopdf.o fuzz_texttopdf.c
	$(CXX) $(CXXFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o fuzz_texttopdf fuzz_texttopdf.o $(LINK_FLAGS) 

fuzz_texttopdf_2:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_texttopdf_2.o fuzz_texttopdf_2.c
	$(CXX) $(CXXFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o fuzz_texttopdf_2 fuzz_texttopdf_2.o $(LINK_FLAGS)

oss_fuzzers:
	cp $(TARGETS) $(OUT)

clean:
	rm -f $(TARGETS) *.o $(TARGETS)