# Fuzzing Harness for go-avahi

This directory contains fuzzers for the [`go-avahi`](https://github.com/OpenPrinting/go-avahi) project.

## Fuzzers

- `fuzz_domain.go`: Targets `DomainNormalize`.
- `fuzz_domain_roundtrip.go`: Verifies round-trip consistency between `DomainFrom` and `DomainSlice`.
- `fuzz_service_name.go`: Tests split/join consistency for service names.
- `fuzz_state_strings.go`: Tests stability of `String()` methods for library states.

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

4. Run a fuzzer:
```bash
python3 infra/helper.py run_fuzzer go-avahi fuzz_domain_normalize
python3 infra/helper.py run_fuzzer go-avahi fuzz_domain_roundtrip
python3 infra/helper.py run_fuzzer go-avahi fuzz_service_name
python3 infra/helper.py run_fuzzer go-avahi fuzz_state_strings
```
