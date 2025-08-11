# IPP-USB Fuzzing

This directory contains fuzzing harnesses for the ipp-usb project, following Alexander Pevzner's guidance on fuzzing both halves of the ipp-usb proxy.

## Fuzzing Strategy

As recommended by Alexander, we implement two complementary approaches:

### 1. USB Layer Fuzzing (Primary)
- **File**: `fuzz_usb_layer.go`
- **Target**: `fuzz_usb_layer`
- **Approach**: Injects fuzzed data at the USB protocol layer using go-mfp's usbip virtual printer
- **Coverage**: Tests ipp-usb's USB-to-HTTP conversion logic

### 2. HTTP Client Fuzzing (Complementary)  
- **File**: `fuzz_http_client.go`
- **Target**: `fuzz_http_client`
- **Approach**: Tests ipp-usb's tolerance to malformed HTTP clients
- **Coverage**: Tests ipp-usb's HTTP server implementation

## Setup Requirements

1. **Kernel Modules**: 
   ```bash
   modprobe usbip-host usbip-core
   ```

2. **USBIP Attachment**:
   ```bash
   usbip attach -r localhost -b 1-1
   ```

3. **Dependencies**:
   - go-mfp (virtual printer implementation)
   - ipp-usb (fuzzing target)

## Architecture

```
Client → ipp-usb → [USB Fuzzing] → Virtual Printer (go-mfp/usbip)
[HTTP Fuzzing] → ipp-usb → Real/Virtual Printer
```

The fuzzers create controlled, reproducible environments for testing ipp-usb's robustness against malformed inputs from both sides of the proxy.

## Files

- `fuzzer/fuzz_usb_layer.go` - USB protocol layer fuzzer
- `fuzzer/fuzz_http_client.go` - HTTP client fuzzer  
- `seeds/*.bin` - Binary IPP and USB protocol seed data
- `seeds/*.txt` - HTTP request seed data
- `README.md` - This file

## Usage

These files are designed for integration with OSS-Fuzz. When deployed, OSS-Fuzz will:

1. Build the fuzzers using the build scripts
2. Create seed corpus archives from the seeds/ directory
3. Run continuous fuzzing with coverage feedback
4. Report any crashes or hangs found

For local testing, you can run:
```bash
go test -fuzz=FuzzUSBLayer ./fuzzer
go test -fuzz=FuzzHTTPClient ./fuzzer
```
