#!/bin/bash -eu

# Build poppler static library for fuzz_texttopdf
git clone https://gitlab.freedesktop.org/poppler/poppler.git && cd poppler
mkdir build && pushd build
cmake .. -DBUILD_SHARED_LIBS=OFF -DENABLE_CPP=ON -DENABLE_GPGME=OFF -DENABLE_QT6=OFF -DENABLE_BOOST=OFF -DENABLE_LIBCURL=OFF -DENABLE_NSS3=OFF -DENABLE_QT5=OFF -DENABLE_LIBOPENJPEG=unmaintained
make
cp libpoppler.a cpp/libpoppler-cpp.a /usr/lib/x86_64-linux-gnu/
popd

# Prepare shared libraries
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/liblcms2.so* $OUT/lib/

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
pushd $SRC/fuzzing/projects/cups-filters/
# Show fuzzer version
echo "OpenPrinting/fuzzing version: $(git rev-parse HEAD)"
cp -r $SRC/fuzzing/projects/cups-filters/fuzzer $SRC/cups-filters/ossfuzz/
popd

# Build cups-filters
pushd $SRC/cups-filters

# Show build version
echo "cups-filters version: $(git rev-parse HEAD)"

# For libppd-dev in cups-filters-2.x
# export LIBPPD_CFLAGS="-I/usr/include"
# export LIBPPD_LIBS="-L/usr/lib -lppd"

# For multiple definition of `_cups_isalpha', `_cups_islower`, `_cups_toupper`
export LDFLAGS="$LDFLAGS -Wl,--allow-multiple-definition" # rather important without this, the build will fail

./autogen.sh
./configure --enable-static --disable-shared
make # -j$(nproc)
popd

pushd $SRC/cups-filters/ossfuzz/
# Build fuzzers
# make
# make oss_fuzzers

# Temporarily do nothing
echo "Do nothing"

# for fuzz_texttopdf
# patchelf --set-rpath '$ORIGIN/lib' $OUT/fuzz_texttopdf

popd

# Prepare corpus
pushd $SRC/fuzzing/projects/cups-filters/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd

# For build poppler static library
# git clone https://gitlab.freedesktop.org/poppler/poppler.git
# mkdir build
# cd build
# cmake .. -DBUILD_SHARED_LIBS=OFF -DENABLE_CPP=ON -DENABLE_GPGME=OFF -DENABLE_QT6=OFF -DENABLE_BOOST=OFF -DENABLE_LIBCURL=OFF -DENABLE_NSS3=OFF -DENABLE_QT5=OFF -DENABLE_LIBOPENJPEG=unmaintained
# make