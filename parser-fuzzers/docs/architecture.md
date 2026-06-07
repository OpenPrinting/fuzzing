# Layered Architecture

This project is organized around a three-system loop:

```text
Generator/SMT system
  -> structured seeds and repaired inputs
  -> runner or AFL++

AFL++ / fuzzer system
  -> queue, crashes, hangs, fuzzer_stats
  -> feedback import

Feedback / metrics system
  -> shape, crash, corpus, coverage, and metrics summaries
  -> next generator round
```

SMT is intentionally kept outside AFL++. AFL++ only needs inputs,
dictionaries, a target command, and optionally CmpLog/custom-mutator support.

## Layer Map

```text
Layer 0: Core schemas and config
  core/models.py
  core/validation.py
  core/hashing.py
  core/experiment.py
  core/format_specs.py

Layer 1: Generator and SMT
  generator/solver.py
  generator/z3_guard.py
  generator/patcher.py
  generator/template_synth.py
  generator/ppd_templates.py
  generator/image_templates.py
  generator/structured_templates.py
  generator/structure_mutator.py
  generator/dimension_expander.py
  generator/auto_expand.py
  generator/constraint_repair.py
  generator/arithmetic_explorer.py

Layer 2: Execution runner
  runner/cli.py
  runner/document_harness.py
  runner/multitarget_runner.py
  runner/cupsfilter.py
  runner/ppd_pipeline.py

Layer 3: AFL++ boundary
  afl_integration/afl.py
  afl_integration/afl_feedback.py
  afl_integration/seed_export.py
  scripts/run_afl.sh
  scripts/build_afl_template_probe.sh
  scripts/run_template_afl_loop.sh
  scripts/run_afl_pwg_frontier.sh
  scripts/afl_direct_filter_target.sh
  scripts/prepare_afl_frontier_corpus.py
  scripts/import_afl_frontier_feedback.py

Layer 4: Feedback, triage, and metrics
  feedback/template_feedback.py
  feedback/output_feedback.py
  feedback/semantic_shapes.py
  feedback/crash_avoidance.py
  feedback/crash_dedup.py
  metrics/run_metrics.py
  metrics/loop_metrics.py
  metrics/run_set_metrics.py
  metrics/run_recovery.py
  metrics/baseline_compare.py
```

## Data Flow

### Template-Only Exploration

```text
configs/parser_targets_*.yaml
  -> multitarget-monitor
  -> document_harness
  -> structured_templates + template_synth
  -> target filter process
  -> timeline.jsonl + summary.json
  -> crash_dedup + run_metrics
```

Use this when there is no good AFL++ harness yet, or when the goal is to
measure structured template reachability directly.

### Standard AFL++ Exploration

```text
template export / public seeds / SMT corpus
  -> AFL++ seed directory
  -> afl-fuzz -i ... -o ... [-x dict] [-c cmplog] -- target @@
  -> AFL++ queue/crashes/hangs
  -> summarize-run-metrics --afl-output-dir ...
```

The standard command builder is `src/parser_fuzzers/afl.py`. It produces regular
AFL++ invocations with `-i`, `-o`, `-m`, `-t`, optional `-x`, optional `-c`,
`-V` when requested, and `@@`. `export-template-seeds` is the bridge from a
template run's retained corpus to AFL++ `-i`.

The clone-only AFL++ probe harness is intentionally small:

```text
scripts/build_afl_template_probe.sh
  -> afl-clang-fast harnesses/afl_template_probe.c
  -> work/afl/bin/template_probe
```

It exists to verify that the project uses normal AFL++ instrumentation and
fuzzer_stats. Real CUPS/cups-filters harnesses should use the same AFL++
boundary but point `--binary` at an instrumented target.

### AFL++ Frontier Feedback Loop

```text
template seeds
  -> AFL++ run
  -> import queue/crashes
  -> build template feedback profile
  -> generate next template round
  -> AFL++ run
```

The current implementation is file-backed rather than in-memory. This keeps
each round reproducible and makes it easy to inspect AFL++ artifacts.
`scripts/run_template_afl_loop.sh` runs one template -> AFL++ -> feedback
template cycle and writes `loop_manifest.json` plus `loop_standard_metrics.json`.

## Layer Boundaries

Generator/SMT layer:

- Creates structured inputs.
- Solves or repairs typed fields.
- Should not own long-running process scheduling.
- Should not interpret AFL++ `queue/` or `crashes/` directly.

Runner layer:

- Owns target execution.
- Writes per-case artifacts.
- Applies runtime skip and corpus-retention policy.
- Does not need to know how AFL++ mutates bytes.

AFL++ boundary:

- Prepares seed directories and dictionaries.
- Starts AFL++ or prints a dry-run command.
- Imports AFL++ output back into runner-compatible feedback cases.
- Does not need to understand SMT internals.

Feedback/metrics layer:

- Reads completed runs.
- Extracts semantic shapes, crash signatures, corpus density, and coverage.
- Writes summaries and profiles for the next round.
- Should be side-effect-light except for output reports/profiles.

## Current AFL++ Status

There are two AFL++ modes in the repository:

1. Standard command generation

   `scripts/run_afl.sh` and `src/parser_fuzzers/afl.py` generate normal AFL++
   commands. This is the preferred path for real instrumented harnesses.

2. Direct filter bridge

   `scripts/run_afl_pwg_frontier.sh` and
   `scripts/afl_direct_filter_target.sh` can drive existing filters through a
   wrapper. When `AFL_DIRECT_INSTRUMENTED=1` is not set, this uses AFL++ dumb
   mode (`-n`). That is useful for fast black-box probing, but it is not the
   same as coverage-guided AFL++.

## Compatibility Imports

The implementation now lives in layer subpackages:

```text
src/parser_fuzzers/core/
src/parser_fuzzers/generator/
src/parser_fuzzers/runner/
src/parser_fuzzers/afl_integration/
src/parser_fuzzers/feedback/
src/parser_fuzzers/metrics/
```

The historical flat imports remain available through compatibility wrappers.
For example, both imports work:

```python
from parser_fuzzers.solver import solve_event
from parser_fuzzers.generator.solver import solve_event
```

New code should prefer the layer path when it is already clear which layer it
belongs to. Existing scripts and tests can continue to use the flat imports
until they are mechanically updated.
