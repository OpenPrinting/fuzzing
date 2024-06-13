#!/bin/bash -eu

# Export flags for libfuzzer with ASan and UBSan
export CC=clang
export CXX=clang++
export CFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export CXXFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"

# generate position-independent code
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

# Build local
./configure --enable-static --disable-shared
make -j$(nproc)

# Build fuzzer
pushd fuzzing/cups/
make
popd

# Run locally setup
mkdir -p fuzzing/cups/fuzz_cups_seed/
mkdir -p fuzzing/cups/fuzz_ipp_seed/
mkdir -p fuzzing/cups/fuzz_raster_seed/

echo ""
echo "Run: ./fuzzing/\${fuzzer} fuzzing/\${fuzzer}_seed fuzzing/\${fuzzer}_seed_corpus"
echo ""
