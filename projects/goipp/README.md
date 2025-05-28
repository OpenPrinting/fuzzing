# Fuzzing Harness for goipp

This directory contains fuzzers for the [`goipp`](https://github.com/OpenPrinting/goipp) project.

## Fuzzer

- `fuzz_decode_bytes.go`: Fuzzes the `DecodeBytes` function in `message.go`.
- `fuzz_decode_bytes_ex.go`: Fuzzes the `DecodeBytesEx` function in `message.go`.

### TODO:

- after successfully building and running the harnesses using oss-fuzz locally, update readme with instructions for the same