#!/bin/bash -eu

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$(echo "$CXXFLAGS" | sed 's/-stdlib=libc++//g') -fPIE"

FUZZER_DIR=$SRC/fuzzing/projects/cups-filters

# for libtool usage
export PATH=$PATH:$SRC/cups-filters
cp $FUZZER_DIR/fuzzer/patch_qpdf_xobject $SRC/cups-filters/filter/pdftopdf/

echo "OpenPrinting/fuzzing version: $(git -C $FUZZER_DIR rev-parse HEAD)"

# Build cups-filters
pushd $SRC/cups-filters
echo "cups-filters version: $(git rev-parse HEAD)"

# For multiple definition of `_cups_isalpha', `_cups_islower`, `_cups_toupper`
export LDFLAGS="${LDFLAGS:-} -Wl,--allow-multiple-definition"

### Temporal fix bug due to libqpdf-dev 9
pushd $SRC/cups-filters/filter/pdftopdf/
patch < patch_qpdf_xobject
popd

./autogen.sh
./configure --enable-static --disable-shared
make # -j$(nproc)

# Build the fuzzer(s) via the fuzzer Makefile (also used for local builds).
cp -r $FUZZER_DIR/fuzzer ossfuzz
make -C ossfuzz
make -C ossfuzz ossfuzz
popd

# Prepare corpus
pushd $FUZZER_DIR/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
