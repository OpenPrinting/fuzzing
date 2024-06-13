CUPS=fuzz_cups
IPP=fuzz_ipp
RES=fuzz_raster

BUILDTOP=./../../cups

INCLUDE=\
	-I$(BUILDTOP)\
	-I$(BUILDTOP)/cups/

# `ALL_CFLAGS` are copied from the make process.
ALL_CFLAGS=\
	-D_CUPS_SOURCE -D_FORTIFY_SOURCE=3 -D_REENTRANT  -D_LARGEFILE_SOURCE\
	-D_LARGEFILE64_SOURCE -D_THREAD_SAFE -D_REENTRANT\
	-Wall -Wunused -Wno-char-subscripts -Wno-deprecated-declarations\
	-Wno-format-y2k -Wno-switch -Wno-unused-result

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

all: $(CUPS) $(IPP) $(RES)

# Using `CXX` as linker
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements

$(CUPS):
	$(CC) $(CFLAGS) $(ALL_CFLAGS) $(INCLUDE) -c $(CUPS).c
	$(CXX) $(CFLAGS) -o $(CUPS) $(CUPS).o $(ALL_LDFLAGS)

$(IPP):
	$(CC) $(CFLAGS) $(ALL_CFLAGS) $(INCLUDE) -c $(IPP).c
	$(CXX) $(CFLAGS) -o $(IPP) $(IPP).o $(ALL_LDFLAGS)

$(RES):
	$(CC) $(CFLAGS) $(ALL_CFLAGS) $(INCLUDE) -c $(RES).c
	$(CXX) $(CFLAGS) -o $(RES) $(RES).o $(ALL_LDFLAGS)

clean:
	rm $(CUPS) $(IPP) $(RES) *.o

.PHONY: CUPS IPP RES clean