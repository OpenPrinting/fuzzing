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

# prepare fuzz dir
cp -r $SRC/fuzzing/projects/cups/fuzzer $SRC/cups/oss-fuzz/

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
