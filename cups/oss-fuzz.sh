#!/bin/bash -eu

# build project
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$CFLAGS -fPIE"
export LDFLAGS="$CFLAGS -fPIE"

./configure --enable-static --disable-shared
make

# build fuzzers
pushd $SRC/cups/oss-fuzz/
make
cp FuzzCUPS $OUT/FuzzCUPS
cp FuzzIPP $OUT/FuzzIPP
cp FuzzRaster $OUT/FuzzRaster
popd

# prepare corpus
pushd $SRC/fuzzing/projects/cups/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
