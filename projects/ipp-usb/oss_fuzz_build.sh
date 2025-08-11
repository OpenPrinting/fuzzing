#!/bin/bash -eu

mkdir -p $SRC/ipp-usb/fuzzer
cp $SRC/fuzzing/projects/ipp-usb/fuzzer/fuzz_usb_layer.go $SRC/ipp-usb/fuzzer/
cp $SRC/fuzzing/projects/ipp-usb/fuzzer/fuzz_http_client.go $SRC/ipp-usb/fuzzer/
cp $SRC/fuzzing/projects/ipp-usb/fuzzer/fuzz_daemon_integration.go $SRC/ipp-usb/fuzzer/

# Create seed corpus (zip)
mkdir -p $WORK/usb_ipp_seed_corpus
if [ -d "$SRC/fuzzing/projects/ipp-usb/seeds" ]; then
    find $SRC/fuzzing/projects/ipp-usb/seeds -name "*.bin" -exec cp {} $WORK/usb_ipp_seed_corpus/ \;
fi
cd $WORK
if [ "$(ls -A usb_ipp_seed_corpus)" ]; then
    zip -r $OUT/fuzz_usb_layer_seed_corpus.zip usb_ipp_seed_corpus/
    zip -r $OUT/fuzz_daemon_integration_seed_corpus.zip usb_ipp_seed_corpus/
fi

mkdir -p $WORK/http_seed_corpus
if [ -d "$SRC/fuzzing/projects/ipp-usb/seeds" ]; then
    find $SRC/fuzzing/projects/ipp-usb/seeds -name "*.txt" -exec cp {} $WORK/http_seed_corpus/ \;
fi
if [ "$(ls -A http_seed_corpus)" ]; then
    zip -r $OUT/fuzz_http_client_seed_corpus.zip http_seed_corpus/
fi

# Build ipp-usb binary
cd $SRC/ipp-usb
go mod tidy
CGO_ENABLED=1 go build -o ipp-usb .


# Build fuzzers
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer ./fuzzer FuzzUSBLayer fuzz_usb_layer
compile_native_go_fuzzer ./fuzzer FuzzHTTPClient fuzz_http_client
compile_native_go_fuzzer ./fuzzer FuzzDaemonIntegration fuzz_daemon_integration