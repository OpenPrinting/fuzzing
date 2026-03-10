#!/bin/bash -eu

# Package seed corpus — domain normalize
mkdir -p $WORK/domain_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/domain_seed_corpus/* $WORK/domain_seed_corpus/
cd $WORK
zip -r $OUT/fuzz_domain_normalize_seed_corpus.zip domain_seed_corpus/

# Package seed corpus — domain round-trip
mkdir -p $WORK/roundtrip_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/roundtrip_seed_corpus/* $WORK/roundtrip_seed_corpus/
zip -r $OUT/fuzz_domain_roundtrip_seed_corpus.zip roundtrip_seed_corpus/

# Package seed corpus — service name
mkdir -p $WORK/service_name_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/service_name_seed_corpus/* $WORK/service_name_seed_corpus/
zip -r $OUT/fuzz_service_name_seed_corpus.zip service_name_seed_corpus/

# Package seed corpus — state strings
mkdir -p $WORK/state_strings_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/state_strings_seed_corpus/* $WORK/state_strings_seed_corpus/
zip -r $OUT/fuzz_state_strings_seed_corpus.zip state_strings_seed_corpus/

# Package seed corpus — string array
mkdir -p $WORK/string_array_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/string_array_seed_corpus/* $WORK/string_array_seed_corpus/
zip -r $OUT/fuzz_string_array_seed_corpus.zip string_array_seed_corpus/

# Package seed corpus — client lifecycle
mkdir -p $WORK/client_lifecycle_seed_corpus
cp $SRC/fuzzing/projects/go-avahi/seeds/client_lifecycle_seed_corpus/* $WORK/client_lifecycle_seed_corpus/
zip -r $OUT/fuzz_client_lifecycle_seed_corpus.zip client_lifecycle_seed_corpus/

# Standard build environment: the library is at /src/go-avahi
# We clean the fuzzer directory first to ensure a fresh start
rm -rf $SRC/go-avahi/fuzzer
mkdir -p $SRC/go-avahi/fuzzer
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_domain.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_domain_roundtrip.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_service_name.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_state_strings.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_string_array.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_client_lifecycle.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_dns.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_entry_group.go $SRC/go-avahi/fuzzer/
cp $SRC/fuzzing/projects/go-avahi/fuzzer/fuzz_service_browser.go $SRC/go-avahi/fuzzer/

# CGo environment: use pkg-config for architecture-agnostic library resolution
export CGO_ENABLED=1
export CGO_CFLAGS="-D_REENTRANT"
export CGO_LDFLAGS="$(pkg-config --libs avahi-client) -lpthread -lresolv"

# Append avahi libs to CXXFLAGS so compile_native_go_fuzzer's final
# clang++ link step can resolve the C symbols from the .a archive.
export CXXFLAGS="${CXXFLAGS:-} $(pkg-config --libs avahi-client) -lpthread -lresolv"

# Copy required shared libraries to $OUT for the runner container
# We use ldconfig to find the exact paths.
for lib in libavahi-client.so.3 libavahi-common.so.3 libdbus-1.so.3 \
           libsystemd.so.0 libgcrypt.so.20 libgpg-error.so.0 \
           liblzma.so.5 liblz4.so.1 libcap.so.2 libz.so.1; do
    LIB_PATH=$(ldconfig -p | grep -m 1 " => .*"$lib | awk '{print $4}')
    if [ -n "$LIB_PATH" ]; then
        cp "$LIB_PATH" "$OUT/"
    fi
done

# Build dependencies and fuzzers
cd $SRC/go-avahi
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer ./fuzzer FuzzDomainNormalize fuzz_domain_normalize
compile_native_go_fuzzer ./fuzzer FuzzDomainRoundTrip fuzz_domain_roundtrip
compile_native_go_fuzzer ./fuzzer FuzzServiceName fuzz_service_name
compile_native_go_fuzzer ./fuzzer FuzzStateStrings fuzz_state_strings
compile_native_go_fuzzer ./fuzzer FuzzStringArray fuzz_string_array
compile_native_go_fuzzer ./fuzzer FuzzClientLifecycle fuzz_client_lifecycle
compile_native_go_fuzzer ./fuzzer FuzzDecodeDNSA fuzz_dns_decode_a
compile_native_go_fuzzer ./fuzzer FuzzDNSAAAA fuzz_dns_decode_aaaa
compile_native_go_fuzzer ./fuzzer FuzzDNSTXT fuzz_dns_decode_txt
compile_native_go_fuzzer ./fuzzer FuzzEntryGroupLifecycle fuzz_entry_group
compile_native_go_fuzzer ./fuzzer FuzzServiceBrowserLifecycle fuzz_service_browser

# RPATH fix: use patchelf to ensure $ORIGIN is set for all binaries
for fuzzer in fuzz_domain_normalize fuzz_domain_roundtrip fuzz_service_name fuzz_state_strings fuzz_string_array fuzz_client_lifecycle fuzz_dns_decode_a fuzz_dns_decode_aaaa fuzz_dns_decode_txt fuzz_entry_group fuzz_service_browser; do
    if [ -f "$OUT/$fuzzer" ]; then
        patchelf --set-rpath '$ORIGIN' "$OUT/$fuzzer"
    fi
done
