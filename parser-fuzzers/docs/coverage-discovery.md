# Coverage Discovery

This mode is for exploring beyond already triaged shallow crashes.

## Entrypoints

Avoid-only coverage discovery on the general target set:

```bash
scripts/run_coverage_discovery_campaign.sh 300 4 5
```

Deep coverage discovery with expanded structural mutation, runtime skip, and
novelty scheduling:

```bash
scripts/run_deep_coverage_campaign.sh 300 4 5
```

## Mechanics

- Known shallow crash predicates are skipped before execution.
- Each executed case extracts feature tokens from target id, PPD kind, document
  kind, document header fields, oracle, return code, and selected stderr state
  lines.
- Coverage-oriented PPD, CUPS Raster, PWG Raster, and image templates are filled
  by SMT slot synthesis. The solver chooses typed fields and cross-field
  relationships; the format builders still write the actual PPD/document bytes.
- Cases that introduce at least one new feature are retained under
  `corpus/interesting/`.
- Crash signatures are normalized and quarantined. The first case per unique
  signature is copied under `quarantine/unique/`; repeats are recorded in
  `quarantine/repeats.jsonl`.
- In deep mode, a crash also suppresses later cases with the same target, PPD
  template slot, and document template slot. This avoids cycling on a confirmed
  shallow shape while leaving other structures in the same parser enabled.
- In deep mode, target selection uses a novelty-weighted fair scheduler:
  targets that keep producing new feature tokens receive more executions, while
  targets dominated by repeated crashes, timeouts, or runtime-suppressed shapes
  are gradually deprioritized.
- Active crash avoidance can softly deweight targets with seeded historical
  suppression pressure while still reserving periodic probe slots. The default
  exploratory command line can set `SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL=32`,
  `SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE=0.06`, and
  `SMT_FUZZER_AVOIDANCE_SCHEDULER_PENALTY_CAP=2.0`.
- In deep mode, ordinary per-case directories are pruned after their timeline
  record is written. Crash, timeout, and new-feature cases are kept.
- Large binary stdout is discarded by default; every case keeps
  `candidate.ppd`, `document.bin`, `command.txt`, `stderr.txt`, and `meta.json`
  only when the case is retained or needs triage.
- `summary.concise.json` reports scheduler settings and per-target stats;
  `discovery_state.json` records suppressed shapes and target scheduler state.

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

Run-level metrics can be summarized with:

```bash
python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir work/auto-hybrid/<run-id> \
  --llvm-coverage-json work/llvm-coverage/coverage.json \
  --output work/metrics/<run-id>.json
```

## Optional AFL++ Coverage

For AFL++ edge coverage, rebuild the target with:

```bash
source scripts/afl_coverage_env.sh
```

Then use the existing AFL++ launch scripts or the generated
`corpus/interesting/` inputs as AFL seed material.
