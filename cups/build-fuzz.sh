#!/bin/bash -eu

# Dependencies for Ubuntu. I'm too lazy to test in Fedora and others.
# apt-get update && apt-get install -y autoconf libtool-bin pkg-config zlib1g-dev libavahi-client-dev libsystemd-dev

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

# Make local
mkdir fuzz_cups_seed/
mkdir fuzz_ipp_seed/
mkdir fuzz_raster_seed/

echo ""
echo "Run: ./fuzzing/\${fuzzer} fuzzing/\${fuzzer}_seed fuzzing/\${fuzzer}_seed_corpus"
echo ""
