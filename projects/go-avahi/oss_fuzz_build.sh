#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Copy fuzzer source into the target library tree
mkdir -p $SRC/go-avahi/fuzzer
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_domain.go $SRC/go-avahi/fuzzer/

# Package seed corpus
mkdir -p $WORK/domain_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/domain_seed_corpus/* $WORK/domain_seed_corpus/
cd $WORK
zip -r $OUT/fuzz_domain_normalize_seed_corpus.zip domain_seed_corpus/

# CGo environment: use pkg-config for architecture-agnostic library resolution
export CGO_ENABLED=1
export CGO_CFLAGS="-D_REENTRANT"
export CGO_LDFLAGS="$(pkg-config --libs avahi-client) -lpthread -lresolv"

# Append avahi libs to CXXFLAGS so compile_native_go_fuzzer's final
# clang++ link step can resolve the C symbols from the .a archive.
export CXXFLAGS="${CXXFLAGS:-} $(pkg-config --libs avahi-client) -lpthread -lresolv"

# Build dependencies and fuzzers
cd $SRC/go-avahi
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer ./fuzzer FuzzDomainNormalize fuzz_domain_normalize
