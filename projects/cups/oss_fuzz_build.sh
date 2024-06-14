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

# Prepare fuzz dir
pushd $SRC/fuzzing/projects/cups/
# Show fuzzer version
echo "OpenPrinting/fuzzing version: $(git rev-parse HEAD)"
cp -r $SRC/fuzzing/projects/cups/fuzzer $SRC/cups/ossfuzz/
popd

# Build CUPS
pushd $SRC/cups
# Show build version
echo "CUPS version: $(git rev-parse HEAD)"
./configure --enable-static --disable-shared
make # -j$(nproc)
popd

pushd $SRC/cups/ossfuzz/
# Build fuzzers
make
cp fuzz_cups $OUT/fuzz_cups
cp fuzz_ipp $OUT/fuzz_ipp
cp fuzz_raster $OUT/fuzz_raster
popd

# Prepare corpus
pushd $SRC/fuzzing/projects/cups/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
