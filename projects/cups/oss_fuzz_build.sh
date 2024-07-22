#!/bin/bash -eu

# Set fPIE
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

# For regular sanitizers
if [[ $SANITIZER != "coverage" ]]; then
    export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
    export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
    export LDFLAGS="-fsanitize=$SANITIZER"
elif [[ $SANITIZER == "undefined" ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize=function"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=function"
    export LDFLAGS="-fno-sanitize=function"
fi

# For fuzz introspector
    if [[ $SANITIZER == "introspector" ]]; then
        export CFLAGS="-O0 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
        export CXXFLAGS="-O0 -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
        export LDFLAGS=""
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
make oss_fuzzers
popd

# Prepare corpus
pushd $SRC/fuzzing/projects/cups/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
