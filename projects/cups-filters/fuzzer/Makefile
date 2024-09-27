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
LINK_FLAGS=-g -O0 -l:libppd.a -l:libcupsfilters.a -l:libcups.a -l:libfontconfig.a -l:libfreetype.a -l:libbz2.a -lz -l:libtiff.a -l:libzstd.a -l:libwebp.a -l:libdeflate.a \
	-l:libjpeg.a -l:liblzma.a -l:libjbig.a -l:libLerc.a -l:libpng.a -l:libsharpyuv.a -l:libexif.a -l:libgnutls.a -l:libtasn1.a -l:libhogweed.a -l:libgmp.a -l:libnettle.a \
	-l:libidn2.a -l:libunistring.a -l:libavahi-client.a -l:libavahi-common.a -l:libdbus-1.a -l:libcap.a -l:libglib-2.0.a -l:libexpat.a \
	-l:libqpdf.a -l:libbrotlidec.a -l:libbrotlicommon.a -l:libpoppler-cpp.a -l:libpoppler.a\
	-l:libp11-kit.so -l:libgssapi_krb5.so.2 -l:liblcms2.so -lsystemd -lpthread\
	-Wl,--allow-multiple-definition

All: $(TARGETS)

fuzz_texttopdf:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_texttopdf.o fuzz_texttopdf.c
	$(CXX) $(CXXFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o fuzz_texttopdf fuzz_texttopdf.o $(LINK_FLAGS) 

oss_fuzzers:
	cp $(TARGETS) $(OUT)

clean:
	rm -f $(TARGETS) *.o $(TARGETS)