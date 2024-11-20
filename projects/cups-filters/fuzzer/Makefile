TARGETS = \
	fuzzpdf \

# CC=clang
# CXX=clang++

# ifeq ($(FUZZING_ENGINE), afl)
#     ifneq ($(SANITIZER), memory)
#         export CC=afl-clang-fast
#         export CXX=afl-clang-fast++
#     endif
# endif

INCDIR=-I./../filter -I./../fontembed -I./../
LIBDIR=-L./../filter -L./../fontembed -L./../ -L./../.libs

BUILD_FLAGS=-g -O0 
LINK_FLAGS=-Wl,--allow-multiple-definition -l:libfontembed.a -l:libtiff.a -l:libjpeg.a
# LIB_FUZZING_ENGINE = -fsanitize=fuzzer,address

All: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pdfutils.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -o pdfutils.o ../filter/pdfutils.c

fuzzpdf: pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzzpdf.o fuzzpdf.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) -o fuzzpdf fuzzpdf.o pdfutils.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)