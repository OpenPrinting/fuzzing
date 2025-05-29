#!/bin/bash -eu

mkdir -p $SRC/goipp/fuzzer
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_decode_bytes.go $SRC/goipp/fuzzer/
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_decode_bytes_ex.go $SRC/goipp/fuzzer/
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_round_trip.go $SRC/goipp/fuzzer/
cp $SRC/fuzzing/projects/goipp/fuzzer/fuzz_collections.go $SRC/goipp/fuzzer/

# Corpus for fuzzers that accept good AND bad messages
mkdir -p $WORK/good_and_bad_ipp_messages_seed_corpus
cp $SRC/fuzzing/projects/goipp/seeds/good_and_bad_ipp_messages_seed_corpus/* $WORK/good_and_bad_ipp_messages_seed_corpus/
cd $WORK
zip -r $OUT/fuzz_decode_bytes_seed_corpus.zip good_and_bad_ipp_messages_seed_corpus/
zip -r $OUT/fuzz_decode_bytes_ex_seed_corpus.zip good_and_bad_ipp_messages_seed_corpus/

# Corpus for fuzzers that expect only valid (good) IPP messages
mkdir -p $WORK/good_ipp_messages_seed_corpus
cp $SRC/fuzzing/projects/goipp/seeds/good_ipp_messages_seed_corpus/* $WORK/good_ipp_messages_seed_corpus/
zip -r $OUT/fuzz_round_trip_seed_corpus.zip good_ipp_messages_seed_corpus/
zip -r $OUT/fuzz_collections_seed_corpus.zip good_ipp_messages_seed_corpus/

# Build goipp fuzzers
cd $SRC/goipp
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzDecodeBytes fuzz_decode_bytes
compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzDecodeBytesEx fuzz_decode_bytes_ex
compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzRoundTrip fuzz_round_trip
compile_native_go_fuzzer github.com/OpenPrinting/goipp/fuzzer FuzzCollections fuzz_collections
