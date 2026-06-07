# OSS-Fuzz Baseline Comparison

This project can compare the semantic SMT-assisted pipeline against an
OSS-Fuzz-style local baseline.

## Docker Boundary

The official OSS-Fuzz workflow is container based. On a machine with Docker,
the usual cups-filters commands are:

```bash
cd /data/pre-gsoc/oss-fuzz
python3 infra/helper.py build_image cups-filters
python3 infra/helper.py build_fuzzers --sanitizer address --engine libfuzzer cups-filters
python3 infra/helper.py run_fuzzer cups-filters <fuzzer-name>
python3 infra/helper.py coverage cups-filters
```

If Docker is unavailable, those commands cannot run locally. The fallback is a
local fair baseline:

- same cups-filters build and same target config as the optimized run
- same time budget, worker count, timeout, and generated input families
- baseline: coverage discovery, round-robin scheduling, no runtime crash-shape
  suppression
- optimized: coverage discovery, novelty scheduling, runtime crash-shape
  suppression, semantic suppression, and deterministic skip probes

This is not an official OSS-Fuzz execution. It is a reproducible local control
group that uses the same metrics contract.

## Run

```bash
scripts/run_baseline_comparison.sh 60 4 5
```

The script uses `work/parser_targets_cold_semantic_llvm.yaml` by default. Set
`SMT_FUZZER_COMPARE_CONFIG` to use another target config.

To keep novelty scheduling but remove crash-reduction guidance:

```bash
SMT_FUZZER_COMPARE_POLICY=no-crash-avoidance \
  scripts/run_baseline_comparison.sh 60 4 5
```

This disables runtime crash-shape suppression, semantic suppression,
generalized skip, deterministic skip probes, short-PNG abort skipping, and the
novelty scheduler's crash/repeat-crash penalties.

Outputs are written under:

```text
work/baseline-comparison/<timestamp>/
  baseline/<run-id>/
  optimized/<run-id>/
  coverage/baseline/
  coverage/optimized/
  metrics/baseline.json
  metrics/optimized.json
  comparison.json
  comparison.md
```

## Metrics

The comparison table reports:

- executed cases
- retained coverage-interesting cases
- semantic coverage feature count
- semantic features per minute
- retained density
- crash density
- unique crash signatures
- LLVM function, line, and branch coverage when coverage profiles are available

Crash count alone is not the main metric. Runtime suppression can reduce repeat
crashes while improving retained density or coverage depth.
