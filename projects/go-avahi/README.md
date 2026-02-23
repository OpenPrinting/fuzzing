# Fuzzing Harness for go-avahi

This directory contains fuzzers for the [`go-avahi`](https://github.com/OpenPrinting/go-avahi) project.

## Fuzzers

- `fuzz_domain.go`: Fuzzes the `DomainNormalize` function to validate the CGo boundary and `unsafe.Pointer` usage.

## Build with OSS-Fuzz locally:
1. Clone the OSS-Fuzz repo:

```bash
git clone https://github.com/google/oss-fuzz
```

2. Navigate into oss-fuzz directory:

```bash
cd oss-fuzz
```

3. Build the fuzzers:
```bash
python3 infra/helper.py build_fuzzers go-avahi
```

4. Run the fuzzer:
```bash
python3 infra/helper.py run_fuzzer go-avahi fuzz_domain_normalize
```
