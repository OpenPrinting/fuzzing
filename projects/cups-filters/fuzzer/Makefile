TARGETS = \
	fuzz_texttopdf

CC=clang
CXX=clang++

INCDIR=-I./../ -I./../filter/
LIBDIR=-L./../filter/ 
BUILD_FLAGS=-g -O0
LINK_FLAGS=-g -O0 -lcupsfilters -lppd

All: $(TARGETS)

fuzz_texttopdf:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_texttopdf.o fuzz_texttopdf.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) $(LINK_FLAGS) -o fuzz_texttopdf fuzz_texttopdf.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)

clean:
	rm -f $(TARGETS) *.o $(TARGETS)