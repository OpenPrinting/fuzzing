# Fuzzing Harness for pycups

This directory contains fuzzers for the [`pycups`](https://github.com/OpenPrinting/pycups) project.

## Fuzzers

Following are the fuzzing harnesses written for the pycups project:

- `fuzz_auth_callback.py`: Fuzz target for `Connection.password_callback()` with fuzzed password strings and contexts
- `fuzz_buffer_handling.py`: Fuzz target for `Connection.writeRequestData()` with different buffer/length edge cases
- `fuzz_file_handling.py`: Fuzz target for `Connection.getFile()` and `Connection.putFile()` using filenames, file descriptors, and file-like objects
- `fuzz_ipp_io.py`: Fuzz target for `IPPRequest.readIO()` and `IPPRequest.writeIO()` using custom read/write/error callbacks
- `fuzz_print_job.py`: Fuzz target for `Connection.printFile()` with fuzzed printer name, filename, title, and options
- `fuzz_printer_management.py`: Fuzz target for `Connection.addPrinter()` with fuzzed parameters and optional PPD object
- `fuzz_UTF8.py`: Fuzz target for string-to-UTF8 and UTF8-to-string conversions across functions like `getPPD()`, `acceptJobs()`, `getJobs()`, and `getJobAttributes()`

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
python3 infra/helper.py build_fuzzers pycups
```

4. run the fuzzer
```bash
python3 infra/helper.py run_fuzzer pycups FuzzerName
```

**Note: replace `FuzzerName` with the name of the fuzzer**

*example:*
```bash
python3 infra/helper.py run_fuzzer pycups fuzz_ipp_io
```