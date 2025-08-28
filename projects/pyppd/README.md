# Fuzzing Harness for pyppd

This directory contains fuzzers for the [`pyppd`](https://github.com/OpenPrinting/pyppd) project.

## Fuzzers

following are the fuzzing harnesses written for the pyppd project:

- `fuzz_archive.py`: Fuzz target for `archiver.archive()` using fuzz input written as a fake `.ppd` file
- `fuzz_compress.py`: Fuzz target for `archiver.compress()` with a mix of plain and gzipped `.ppd` files
- `fuzz_compressor.py`: Fuzz target for `compress()` / `decompress()` round-trip and `compress_file()` in `pyppd.compressor`
- `fuzz_find_files.py`: Fuzz target for `archiver.find_files()` with fuzz-controlled `.ppd` files and search patterns
- `fuzz_ppd.py`: Fuzz target for `ppd.parse()` with raw fuzz input as a `.ppd` file
- `fuzz_read_file_in_syspath.py`: Fuzz target for `archiver.read_file_in_syspath()` with arbitrary filenames
- `fuzz_runner.py`: Fuzz target for `runner.parse_args()` with fuzz input as command-line arguments


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
python3 infra/helper.py build_fuzzers pyppd
```

4. run the fuzzer
```bash
python3 infra/helper.py run_fuzzer pyppd FuzzerName
```

**Note: replace `FuzzerName` with the name of the fuzzer**

*example:*
```bash
python3 infra/helper.py run_fuzzer pyppd fuzz_compressor
```