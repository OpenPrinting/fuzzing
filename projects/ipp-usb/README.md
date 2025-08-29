# Fuzzing Harness for ipp-usb

This directory contains fuzzers for the [`ipp-usb`](https://github.com/OpenPrinting/ipp-usb) project.

## Fuzzers

following are the fuzzing harnesses written for the ipp-usb project:

- `daemon_fuzzer.go`: Fuzzes the actual ipp-usb daemon with malformed HTTP/IPP requests.
- `usb_fuzzer.go`: Fuzzes USB protocol parsing using a mock USB/IP server.
- `http_client_fuzzer.go`: Fuzzes HTTP client code against malicious server responses.

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
python3 infra/helper.py build_fuzzers ipp-usb
```

4. run the fuzzer
```bash
python3 infra/helper.py run_fuzzer ipp-usb FuzzerName
```

**Note: replace `FuzzerName` with the name of the fuzzer**

*example:*
```bash
python3 infra/helper.py run_fuzzer ipp-usb FuzzHTTPClient
```