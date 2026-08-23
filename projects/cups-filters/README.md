# cups-filters OSS-Fuzz integration

The maintained cups-filters harnesses, seed corpora, dictionaries, and build
logic live in [`../../parser-fuzzers`](../../parser-fuzzers). OSS-Fuzz copies
`oss_fuzz_build.sh` to `$SRC/build.sh`; this entry point delegates to that
single upstream-owned implementation.

The integration builds the current split printing stack: CUPS, PDFio,
libcupsfilters, libppd, and cups-filters. It exports 25 continuous libFuzzer
targets plus the existing raw-PDF compatibility target `fuzz_pdf`.
