# Coverage Discovery

This mode is for exploring beyond already triaged shallow crashes.

## Entrypoints

Avoid-only coverage discovery on the general target set:

```bash
scripts/run_coverage_discovery_campaign.sh 300 4 5
```

Deep coverage discovery with expanded structural mutation:

```bash
scripts/run_deep_coverage_campaign.sh 300 4 5
```

## Mechanics

- Known shallow crash predicates are skipped before execution.
- Each executed case extracts feature tokens from target id, PPD kind, document
  kind, document header fields, oracle, return code, and selected stderr state
  lines.
- Cases that introduce at least one new feature are retained under
  `corpus/interesting/`.
- Crash signatures are normalized and quarantined. The first case per unique
  signature is copied under `quarantine/unique/`; repeats are recorded in
  `quarantine/repeats.jsonl`.
- Large binary stdout is discarded by default; every case keeps
  `candidate.ppd`, `document.bin`, `command.txt`, `stderr.txt`, and `meta.json`.

## Current Avoid Predicates

- `known-rastertoescpx-dotrowstep-zero-fpe`
- `known-libppd-65536dpi-fpe`

These are deliberately narrow. They remove already triaged shallow failures
without hiding new sanitizer signatures from the same target.

## Optional LLVM Coverage

The Python feature-retention path works with the current ASan binaries. For
real LLVM source-based coverage, rebuild the target with:

```bash
source scripts/llvm_coverage_env.sh
```

Then run a campaign with:

```bash
SMT_FUZZER_LLVM_PROFILE_DIR=work/llvm-profraw scripts/run_deep_coverage_campaign.sh 300 4 5
```

Merge profiles:

```bash
scripts/merge_llvm_coverage.sh work/llvm-profraw /path/to/filter work/llvm-coverage
```

## Optional AFL++ Coverage

For AFL++ edge coverage, rebuild the target with:

```bash
source scripts/afl_coverage_env.sh
```

Then use the existing AFL++ launch scripts or the generated
`corpus/interesting/` inputs as AFL seed material.
