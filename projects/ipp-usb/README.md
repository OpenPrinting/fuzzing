# Fuzzing Harness for ipp-usb

This directory contains fuzzers for the [`ipp-usb`](https://github.com/OpenPrinting/ipp-usb) project.

## Fuzzers

- `daemon_fuzzer.go`: Fuzzes the actual ipp-usb daemon with malformed HTTP/IPP requests.
- `usb_fuzzer.go`: Fuzzes USB protocol parsing using a mock USB/IP server.
- `http_client_fuzzer.go`: Fuzzes HTTP client code against malicious server responses.

### TODO:

- after successfully building and running the harnesses using oss-fuzz locally, update readme with instructions for the same