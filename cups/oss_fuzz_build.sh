#!/bin/bash -eu

# Set fPIE
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

if [[ $SANITIZER != "coverage" ]]; then
    export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
    export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
    export LDFLAGS="-fsanitize=$SANITIZER"
fi

./configure --enable-static --disable-shared
make # -j$(nproc)

# Build fuzzers
pushd $SRC/fuzzing/cups/
make
cp fuzz_cups $OUT/fuzz_cups
cp fuzz_ipp $OUT/fuzz_ipp
cp fuzz_raster $OUT/fuzz_raster
popd

# Prepare corpus
pushd $SRC/fuzzing/cups/
zip -r $OUT/fuzz_cups_seed_corpus.zip fuzz_cups_seed_corpus/
zip -r $OUT/fuzz_ipp_seed_corpus.zip fuzz_ipp_seed_corpus/
zip -r $OUT/fuzz_raster_seed_corpus.zip fuzz_raster_seed_corpus/
popd
