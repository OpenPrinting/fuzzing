TARGETS = \
	fuzz_texttopdf_2

CC=clang
CXX=clang++

INCDIR=-I./../ -I./../filter/
LIBDIR=-L./../filter/ 
BUILD_FLAGS=-g -O0
LINK_FLAGS=-g -O0 -lcupsfilters -lppd

All: $(TARGETS)

fuzz_texttopdf_2:
	$(CC) $(CFLAGS) $(INCDIR) $(BUILD_FLAGS) -c -o fuzz_texttopdf_2.o fuzz_texttopdf_2.c
	$(CXX) $(CFLAGS) $(LIBDIR) $(LIB_FUZZING_ENGINE) $(LINK_FLAGS) -o fuzz_texttopdf_2 fuzz_texttopdf_2.o $(LINK_FLAGS)

ossfuzz:
	cp $(TARGETS) $(OUT)

clean:
	rm -f $(TARGETS) *.o $(TARGETS)