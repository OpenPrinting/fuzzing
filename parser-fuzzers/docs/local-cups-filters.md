# Local CUPS/cups-filters Testing

The Python smoke path does not need CUPS. Parser campaigns need either system
filters or a local OpenPrinting build. Crash triage should use a local ASan
build; system filters are useful for reachability smoke only.

## Path 1: System Filters Smoke

Use this path when your distribution already provides CUPS and cups-filters.
This does not guarantee sanitizer diagnostics:

```bash
scripts/install_ubuntu_deps.sh --system-filters -y
scripts/check_cups_filters_targets.sh
scripts/run_multitarget_ppd_fuzz.sh 1 4
```

The default filter root is `/usr/lib/cups/filter`. Override it when your system
uses another location:

```bash
export SMT_FUZZER_FILTER_ROOT=/usr/libexec/cups/filter
scripts/check_cups_filters_targets.sh "$SMT_FUZZER_FILTER_ROOT"
scripts/run_local_cups_filters_campaign.sh "$SMT_FUZZER_FILTER_ROOT" 60 4 5
```

## Path 2: Isolated Local ASan Build

Recommended for crash discovery and issue reports. This keeps source,
intermediate objects, and the install prefix under `work/openprinting-asan/`.
It does not install into `/usr`, `/usr/local`, or any system path.

Print a build plan for `libcupsfilters`, `libppd`, and `cups-filters`:

```bash
scripts/install_ubuntu_deps.sh --asan-build -y
scripts/print_cups_filters_build_plan.sh
```

The script prints commands instead of running them. This keeps dependency
installation and network fetches explicit. The generated plan uses:

```bash
work/openprinting-asan/src
work/openprinting-asan/prefix
```

After building, run:

```bash
scripts/run_asan_cups_filters_campaign.sh work/openprinting-asan 60 4 5
```

For the expanded 20-target profile:

```bash
scripts/run_asan_cups_filters_campaign.sh work/openprinting-asan 300 4 5 configs/parser_targets_coverage.yaml
```

The ASan runner exports these variables for you:

```bash
SMT_FUZZER_FILTER_ROOT=work/openprinting-asan/src/cups-filters
SMT_FUZZER_LD_LIBRARY_PATH=work/openprinting-asan/src/libcupsfilters/.libs:work/openprinting-asan/src/libppd/.libs:work/openprinting-asan/prefix/lib:work/openprinting-asan/prefix/lib64
SMT_FUZZER_ASSUME_ASAN=1
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86
```

## Outputs

Each run creates a timestamped directory under `work/` with:

- `run_manifest.json`: config, target list, and guidance policy.
- `commands.txt`: exact command line for every executed case.
- `timeline.jsonl`: one compact JSON record per case.
- `summary.json` and `summary.concise.json`: aggregate counters.
- per-case `candidate.ppd`, `document.*`, `stderr.txt`, `stdout.bin`, and
  `meta.json`.
- `crash_dedup.json` and `crash_dedup.md` when unique crash signatures are
  found.

## Recent Local Smoke Result

In the development environment, a short discovery-only run used:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config configs/parser_targets.yaml \
  --work-root work/discovery-only-smoke \
  --workers 2 \
  --cases-per-target 1 \
  --timeout-sec 5 \
  --discard-stdout
```

It reached all four configured targets, produced four valid PPDs, and observed
one `signal 11` from the generic direct `rastertopclx` CUPS Raster path. That
case did not use a string-format payload or a known reproduction input.
