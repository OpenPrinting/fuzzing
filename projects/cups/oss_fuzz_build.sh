#!/bin/bash -eu

# Set fPIE
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

if [[ $SANITIZER != "coverage" ]]; then
    export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
    export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
    export LDFLAGS="-fsanitize=$SANITIZER"
elif [[ $SANITIZER == "undefined" ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize=function"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=function"
    export LDFLAGS="-fno-sanitize=function"
fi

# Show build version
echo "CUPS version: $(git rev-parse HEAD)"

# Build CUPS
./configure --enable-static --disable-shared
make # -j$(nproc)

pushd $SRC/fuzzing/cups/
# Show fuzzer version
echo "OpenPrinting/fuzzing version: $(git rev-parse HEAD)"
# Build fuzzers
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
