TARGETS = \
	test_pdf

CC=clang
CXX=clang++

INCDIR=-I./../filter -I./../fontembed -I./../
LIBDIR=-L./../filter -L./../fontembed

BUILD_FLAGS=-g -O0 
# LINK_FLAGS=-l:libfontembed.la
LDADD = ../libfontembed.la

All: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

pdfutils.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -o pdfutils.o ../filter/pdfutils.c

test_pdf: pdfutils.o
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o test_pdf.o test_pdf.c
	libtool --mode=link --tag=CXX $(CXX) $(CFLAGS) $(LIBDIR) $(LINK_FLAGS) -o test_pdf test_pdf.o pdfutils.o $(LDADD)