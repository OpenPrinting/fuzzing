# parser_fuzzers Module Map

The package is split into layer subpackages. Historical flat imports such as
`parser_fuzzers.solver` are kept as compatibility wrappers.

## Core

- `core/models.py`: branch events and solver result models.
- `core/validation.py`: bug/config validation.
- `core/hashing.py`: small hashing helpers.
- `core/experiment.py`: A0-A4 experiment matrix helpers.
- `core/format_specs.py`: format-specific constants and specs.

## Generator And SMT

- `generator/solver.py`: Z3-backed branch-event solver.
- `generator/z3_guard.py`: Z3 availability and guarded solving.
- `generator/patcher.py`: apply solver patches to input bytes.
- `generator/template_synth.py`: typed template slot filling.
- `generator/ppd_templates.py`: PPD templates.
- `generator/image_templates.py`: image input templates.
- `generator/structured_templates.py`: structured PPD/Raster/PWG/template builders.
- `generator/structure_mutator.py`: structure-aware mutations.
- `generator/dimension_expander.py`: automatic template dimension expansion.
- `generator/auto_expand.py`: automatic seed/template expansion driver.
- `generator/constraint_repair.py`: repair related fields after mutation.
- `generator/arithmetic_explorer.py`: cross-input arithmetic/boundary exploration.

## Runner

- `runner/cli.py`: command-line entrypoint.
- `runner/document_harness.py`: materialize PPD/document inputs and commands.
- `runner/multitarget_runner.py`: scheduling, execution, retention, skip policy.
- `runner/cupsfilter.py`: cupsfilter-specific smoke target helpers.
- `runner/ppd_pipeline.py`: PPD template pipeline helpers.

## AFL++ Boundary

- `afl_integration/afl.py`: AFL++ command/corpus/dictionary/CmpLog plan builder.
- `afl_integration/afl_feedback.py`: import AFL++ queue/crash outputs into runner feedback.
- `afl_integration/seed_export.py`: export retained template documents into AFL++ seed directories.

## Feedback, Triage, And Metrics

- `feedback/template_feedback.py`: build feedback profiles from retained cases.
- `feedback/output_feedback.py`: output-derived feedback extraction.
- `feedback/semantic_shapes.py`: semantic shape extraction.
- `feedback/crash_avoidance.py`: known crash-shape suppression helpers.
- `feedback/crash_dedup.py`: crash signature normalization and representative choice.
- `metrics/run_metrics.py`: standard run metrics.
- `metrics/loop_metrics.py`: template/AFL++/feedback loop metrics aggregation.
- `metrics/run_set_metrics.py`: multi-run metric summaries.
- `metrics/run_recovery.py`: recover/summarize interrupted runs.
- `metrics/baseline_compare.py`: baseline and LLVM coverage comparison helpers.

## Import Boundary Rule

Prefer importing across layers in this direction:

```text
core -> generator -> runner -> feedback/metrics
core -> afl boundary -> feedback/metrics
```

Avoid making generator code depend on AFL++ output formats. Import AFL++ output
through `afl_feedback.py` first, then feed the normalized cases into feedback
or template-generation code.
