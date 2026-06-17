# Build the cups-filters PDF-parsing fuzzer(s).
#
# Works both:
#   * under OSS-Fuzz   -- CC/CXX/CFLAGS/CXXFLAGS/LIB_FUZZING_ENGINE/OUT come from
#                         the environment; `make && make ossfuzz`.
#   * for local builds -- run from inside a built cups-filters tree (e.g. after
#                         copying this dir to cups-filters/ossfuzz/); the
#                         defaults below give a usable libFuzzer+ASan binary.

CC  ?= clang
CXX ?= clang++
# Local default engine (OSS-Fuzz overrides this with its own libFuzzer engine).
LIB_FUZZING_ENGINE ?= -fsanitize=fuzzer,address
OUT ?= .

# Path to the (built) cups-filters source tree relative to this directory.
CUPS_FILTERS ?= ..

QPDF_CFLAGS := $(shell pkg-config --cflags libqpdf 2>/dev/null)
QPDF_LIBS   := $(shell pkg-config --libs libqpdf 2>/dev/null || echo -lqpdf)
CUPS_LIBS   := $(shell cups-config --libs 2>/dev/null || echo -lcups)

INCDIR := -I$(CUPS_FILTERS)/filter/pdftopdf -I$(CUPS_FILTERS)/filter -I$(CUPS_FILTERS) $(QPDF_CFLAGS)

# pdftopdf processor objects produced by the cups-filters build, minus the one
# that defines main() (pdftopdf-pdftopdf.o).
PDFTOPDF_OBJS := $(filter-out %/pdftopdf-pdftopdf.o,\
    $(wildcard $(CUPS_FILTERS)/filter/pdftopdf/pdftopdf-*.o))

FUZZERS := fuzz_pdf

all: $(FUZZERS)

fuzz_pdf: fuzz_pdf.cc
	$(CXX) $(CXXFLAGS) -std=c++17 $(INCDIR) -c -o fuzz_pdf.o fuzz_pdf.cc
	$(CXX) $(CXXFLAGS) fuzz_pdf.o $(PDFTOPDF_OBJS) \
	    $(CUPS_FILTERS)/.libs/libcupsfilters.a \
	    $(LIB_FUZZING_ENGINE) $(QPDF_LIBS) $(CUPS_LIBS) \
	    -Wl,--allow-multiple-definition -o fuzz_pdf

clean:
	rm -f *.o $(FUZZERS)

# OSS-Fuzz packaging: copy the fuzzer(s) to $OUT and bundle their shared-library
# closure alongside with RPATH=$ORIGIN, because the base-runner image lacks
# libqpdf/libcups and their transitive deps (avahi, gnutls stack, ...).
# (Not needed for local runs, where the system libraries are present.)
ossfuzz: $(FUZZERS)
	for f in $(FUZZERS); do \
	    cp $$f $(OUT)/; \
	    ldd $(OUT)/$$f | awk '/=> \//{print $$3}' | while read -r so; do \
	        b=$$(basename $$so); \
	        case $$b in \
	            libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|ld-linux*) continue;; \
	        esac; \
	        cp -L $$so $(OUT)/$$b; \
	    done; \
	    patchelf --force-rpath --set-rpath '$$ORIGIN' $(OUT)/$$f; \
	done

.PHONY: all clean ossfuzz
