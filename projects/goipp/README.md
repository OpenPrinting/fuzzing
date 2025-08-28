# Fuzzing Harness for goipp

This directory contains fuzzers for the [`goipp`](https://github.com/OpenPrinting/goipp) project.

## Fuzzers

following are the fuzzing harnesses written for the goipp project:

- `fuzz_decode_bytes.go`: Fuzzes the `DecodeBytes` function in `message.go`.
- `fuzz_decode_bytes_ex.go`: Fuzzes the `DecodeBytesEx` function in `message.go`.
- `fuzz_collections.go`: Fuzz target for goipp's handling of Collection attributes
- `fuzz_round_trip.go`: Fuzz target for goipp's EncodeBytes + DecodeBytes round-trip consistency.
- `fuzz_tag_extension.go`: Fuzz target for goipp's TagExtension handling

## Build with OSS-Fuzz locally:
1. clone the OSS-Fuzz repo:

```bash
git clone https://github.com/google/oss-fuzz
```

2. navigate into oss-fuzz directory:

```bash
cd oss-fuzz
```

3. build the fuzzers
```bash
python3 infra/helper.py build_fuzzers goipp
```

4. run the fuzzer
```bash
python3 infra/helper.py run_fuzzer goipp FuzzerName
```

**Note: replace `FuzzerName` with the name of the fuzzer**

*example:*
```bash
python3 infra/helper.py run_fuzzer goipp FuzzDecodeBytes
```
