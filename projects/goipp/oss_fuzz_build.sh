#!/bin/bash -eu

mkdir -p $SRC/goipp/fuzzer
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_decode_bytes.go $SRC/goipp/fuzzer/
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_decode_bytes_ex.go $SRC/goipp/fuzzer/

# seed corpus for FuzzDecodeBytes
mkdir -p $WORK/fuzz_decode_bytes_corpus
cp $SRC/fuzzing/projects/goipp/seeds/fuzz_decode_bytes_seed_corpus/* $WORK/fuzz_decode_bytes_corpus/
cd $WORK
zip -r $OUT/fuzz_decode_bytes_seed_corpus.zip fuzz_decode_bytes_corpus/

# seed corpus for FuzzDecodeBytesEx
mkdir -p $WORK/fuzz_decode_bytes_ex_corpus
cp $SRC/fuzzing/projects/goipp/seeds/fuzz_decode_bytes_ex_seed_corpus/* $WORK/fuzz_decode_bytes_ex_corpus/
zip -r $OUT/fuzz_decode_bytes_ex_seed_corpus.zip fuzz_decode_bytes_ex_corpus/


# build dependencies and fiuzzers
cd $SRC/goipp
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzDecodeBytes fuzz_decode_bytes
compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzDecodeBytesEx fuzz_decode_bytes_ex
