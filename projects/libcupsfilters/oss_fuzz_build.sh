#!/bin/bash -eu

# Set fPIE
# export CFLAGS="$CFLAGS -fPIE"
# export CXXFLAGS="$CFLAGS -fPIE"
# export LDFLAGS="$CFLAGS -fPIE"

export CFLAGS="-fPIE"
export CXXFLAGS="-fPIE"
export LDFLAGS="-fPIE"

export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
export LDFLAGS="-fsanitize=$SANITIZER"

# For regular sanitizers
if [[ $SANITIZER == "coverage" ]]; then
    export CFLAGS=""
    export CXXFLAGS=""
    export LDFLAGS=""
elif [[ $SANITIZER == "undefined" ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize=function"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=function"
    export LDFLAGS="-fno-sanitize=function"
fi

# For fuzz introspector
if [[ $SANITIZER == "introspector" ]]; then
    export CFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export CXXFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export LDFLAGS="-flto"
fi

# Prepare fuzz dir
pushd $SRC/fuzzing/projects/libcupsfilters/
# Show fuzzer version
echo "OpenPrinting/fuzzing version: $(git rev-parse HEAD)"
cp -r $SRC/fuzzing/projects/libcupsfilters/fuzzer $SRC/libcupsfilters/ossfuzz/
popd

# Build libcupsfilters
pushd $SRC/libcupsfilters

# Show build version
echo "libcupsfilters version: $(git rev-parse HEAD)"

# For libppd-dev in libcupsfilters-2.x
# export LIBPPD_CFLAGS="-I/usr/include"
# export LIBPPD_LIBS="-L/usr/lib -lppd"

# For multiple definition of `_cups_isalpha', `_cups_islower`, `_cups_toupper`
export LDFLAGS="$LDFLAGS -Wl,--allow-multiple-definition"

./autogen.sh
./configure --enable-static --disable-shared
make # -j$(nproc)
popd

pushd $SRC/libcupsfilters/ossfuzz/
# Build fuzzers
make
make oss_fuzzers
popd

# Prepare corpus
pushd $SRC/fuzzing/projects/libcupsfilters/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
