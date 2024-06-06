#!/bin/bash -eu

# Set fPIE
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

./configure --enable-static --disable-shared
make -j$(nproc)

# Build fuzzers
pushd $SRC/cups/fuzzing/cups/
make
cp fuzz_cups $OUT/fuzz_cups
cp fuzz_ipp $OUT/fuzz_ipp
cp fuzz_raster $OUT/fuzz_raster
popd

# Prepare corpus
pushd $SRC/cups/fuzzing/cups/
zip -r $OUT/fuzz_cups_seed_corpus.zip fuzz_cups_seed_corpus/
zip -r $OUT/fuzz_ipp_seed_corpus.zip fuzz_ipp_seed_corpus/
zip -r $OUT/fuzz_raster_seed_corpus.zip fuzz_raster_seed_corpus/
popd
