#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# show fuzzing version
pushd $SRC/fuzzing/
echo "libcups version: $(git rev-parse HEAD)"
popd

# prepare fuzz dir
cp -r $SRC/fuzzing/projects/libcups/fuzzer/. $SRC/libcups/ossfuzz/

# build project
cd $SRC/libcups
git submodule update --init --recursive

# For regular sanitizers
if [[ $SANITIZER != "coverage" ]]; then
    export CFLAGS="$CFLAGS -fsanitize=$SANITIZER"
    export CXXFLAGS="$CXXFLAGS -fsanitize=$SANITIZER"
    export LDFLAGS="-fsanitize=$SANITIZER"
fi

# For fuzz introspector
if [[ $SANITIZER == "introspector" ]]; then
    export CFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export CXXFLAGS="-O0 -flto -fno-omit-frame-pointer -gline-tables-only -Wno-error=enum-constexpr-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=implicit-int -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g"
    export LDFLAGS="-flto"
fi

# show build version
echo "libcups version: $(git rev-parse HEAD)"

# build libcups
./configure --enable-static --disable-shared
make

# build fuzzers
pushd ossfuzz/
make
make ossfuzz
popd

# prepare corpus
pushd $SRC/fuzzing/projects/libcups/seeds
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd