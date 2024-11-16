TARGETS = \
	testpdf \
	fuzzpdf

CC=clang
CXX=clang++

INCDIR=-I./../filter -I./../fontembed -I./../
LIBDIR=-L./../filter -L./../fontembed

BUILD_FLAGS=-g -O0 
# LINK_FLAGS=-l:libfontembed.la
LDADD = ../libfontembed.la
LIB_FUZZING_ENGINE = -fsanitize=fuzzer,address

All: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pdfutils.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -o pdfutils.o ../filter/pdfutils.c

testpdf: pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o testpdf.o testpdf.c
	libtool --mode=link --tag=CXX $(CXX) $(CFLAGS) $(LIBDIR) $(LINK_FLAGS) -o testpdf testpdf.o pdfutils.o $(LDADD)

fuzzpdf: pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzzpdf.o fuzzpdf.c
	libtool --mode=link --tag=CXX $(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) $(LINK_FLAGS) -o fuzzpdf fuzzpdf.o pdfutils.o $(LDADD)