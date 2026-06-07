# parser-fuzzers

`parser-fuzzers` is a runnable fuzzing toolkit for OpenPrinting parser and
filter paths. It combines format-aware seed/template generation, lightweight
SMT-based field repair, standard AFL++ execution, crash triage, and metrics
export.

The current focus is CUPS, cups-filters, libcupsfilters, and libppd parser
paths where random bytes alone often fail early. A useful test case may need a
valid PPD, a compatible document format, coherent raster geometry, and job
options that let the target reach deeper state.

```text
format templates + public seeds
  -> SMT/fallback field repair
  -> generated PPD + document cases
  -> runner or standard AFL++
  -> queue/hangs/crash candidates + retained corpus
  -> dedup, replay, metrics, optional LLVM coverage
```

Private reproducers, issue reports, and minimized crash inputs are not bundled
with this public toolkit.

## Quick Start

This path checks the project without AFL++, CUPS, private reproducers, or a local
OpenPrinting build.

```bash
git clone <repo-url> openprinting-fuzzing
cd openprinting-fuzzing/parser-fuzzers

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .

scripts/check_env.sh
python3 -m parser_fuzzers.cli validate --bugs bugs --configs configs --allow-missing-local-artifacts
scripts/run_smoke.sh
python3 -m unittest discover -s tests
```

Expected result:

- `validate` exits with zero errors.
- `run_smoke.sh` solves a synthetic branch event, patches one input byte, and
  verifies the patched input.
- The unit test suite passes without external CUPS artifacts.

For a menu-driven local setup:

```bash
scripts/setup_tui.sh
```

To print the same setup commands without entering the menu:

```bash
scripts/setup_tui.sh --commands
```

## Ubuntu Dependencies

Minimal Python smoke path:

```bash
scripts/install_ubuntu_deps.sh --minimal -y
```

AFL++ and triage tools:

```bash
scripts/install_ubuntu_deps.sh --afl -y
```

System CUPS filter probing:

```bash
scripts/install_ubuntu_deps.sh --system-filters -y
```

The helper reports missing tools clearly. AFL++ is optional for the smoke path.

## What SMT Does

SMT is not the fuzzer and it is not symbolic execution of the target program.
It is a constraint-solving helper around the fuzzing pipeline.

Current roles:

- Fill typed template slots such as width, height, bits-per-pixel,
  bytes-per-line, color model, resolution, page count, and option values.
- Repair related fields after structural mutation so inputs survive shallow
  parser checks more often.
- Solve small branch-event JSON constraints and write byte patches for the
  `solve-event` / `patch-input` smoke workflow.

In short:

```text
template/mutator  -> proposes structure and boundary values
SMT               -> keeps dependent fields coherent
AFL++             -> evolves bytes from seed directories
runner            -> executes real targets and records feedback
```

A crash is therefore not automatically "caused by SMT". SMT mainly improves
reachability by making generated inputs coherent enough to reach parser and
filter code that plain random mutation may miss.

## Repository Layout

```text
bugs/          optional local-only bug metadata interface
configs/       target and campaign configurations
dictionaries/  AFL++ dictionaries
docs/          architecture, evaluation, and status notes
harnesses/     AFL++ probe and C harness templates
scripts/       runnable workflows
seeds/public/  weak public seeds only
src/           Python package
tests/         unit tests
work/          generated local outputs, ignored by git
```

The Python package is named `parser_fuzzers`; the project name and console
script are `parser-fuzzers`.

## Main Modes

### 1. Clone-only smoke

```bash
scripts/run_smoke.sh
python3 -m unittest discover -s tests
```

Use this to prove the solver, patcher, validation, and tests are wired.

### 2. Local system filters

This uses filters already installed on the system.

```bash
scripts/check_cups_filters_targets.sh /usr/lib/cups/filter
scripts/run_local_cups_filters_campaign.sh /usr/lib/cups/filter 60 2 5 configs/parser_targets_general.yaml
```

Arguments are:

```text
<filter-root> <duration-sec> <workers> <timeout-sec> <config>
```

### 3. Template/runner exploration

This mode generates structured PPD/document cases and executes configured
targets directly. The wrapper asks for the filter root before running so the
campaign does not silently use a hard-coded local path.

Quick reproducibility check:

```bash
scripts/run_template_runner_campaign.sh 10 1 2 configs/parser_targets_auto_hybrid.yaml
```

Arguments are:

```text
<duration-sec> <workers> <timeout-sec> <config>
```

For non-interactive runs, set `SMT_TEMPLATE_FILTER_ROOT=/path/to/cups-filters`.
Increase the duration, workers, and `SMT_TEMPLATE_MAX_RUN_GB` for longer local
campaigns. The runner writes retained cases, timeline data, triage summaries,
and metrics under `work/`.

### 4. Standard AFL++ from generated seeds

Build the clone-only AFL++ probe harness:

```bash
scripts/build_afl_template_probe.sh work/afl/bin/template_probe
```

Generate structured seeds without executing any OpenPrinting filter:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli generate-template-seeds \
  --document-kind pwg_raster_feedback_sweep \
  --target-id template_probe_pwg \
  --output-dir work/afl/seeds \
  --count 64 \
  --extension .pwg
```

The seed directory contains AFL++ inputs only. Metadata is written next to it,
for example `work/afl/seeds-template_seed_manifest.json`.

Alternatively, after a real template/runner campaign, export retained generated
documents into an AFL++ seed directory:

```bash
template_run="$(find work/template-generate -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
PYTHONPATH=src python3 -m parser_fuzzers.cli export-template-seeds \
  --run-dir "$template_run" \
  --target-id pwg_to_pdf_afl_feedback \
  --extension .pwg \
  --output-dir work/afl/seeds \
  --limit 512
```

Retained-corpus export metadata is also written next to the seed directory, for
example `work/afl/seeds-seed_export_manifest.json`.

Run AFL++ in the standard way:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli afl-run \
  --target template_probe_pwg \
  --config A1 \
  --binary work/afl/bin/template_probe \
  --input-dir work/afl/seeds \
  --output-dir work/afl/out \
  --duration-sec 60 \
  --timeout-ms 1000 \
  --memory-mb 1024 \
  --execute
```

Record standard metrics from the AFL++ output:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir work/afl \
  --afl-output-dir work/afl/out \
  --output work/afl/standard_metrics.json
```

The generated AFL++ command uses normal `afl-fuzz` arguments:

```text
afl-fuzz -i <seeds> -o <out> -t <timeout> -m <mem> [-x dict] [-c cmplog] -- <target> @@
```

Dumb mode is used only when explicitly requested for a non-instrumented target.

### 5. Template -> AFL++ -> feedback loop

This combines a real template/runner pass, a standard AFL++ run, and a feedback
template pass. By default it expects the local filter targets from
`configs/parser_targets_afl_pwg_feedback.yaml`; use mode 4 for the clone-only
template seed plus AFL++ probe flow. The script builds the clone-local probe
automatically if it is missing and asks for the template filter root before
starting an interactive run.

```bash
SMT_TEMPLATE_AFL_WORK_ROOT=work/template-afl-loop \
  PYTHONPATH=src scripts/run_template_afl_loop.sh 180 pwg_to_pdf_afl_feedback .pwg
```

Use a larger first argument for real runs; each phase has a 60-second minimum
so very small values still take about three minutes.

The loop is file-backed:

```text
template run
  -> export AFL++ seeds
  -> standard AFL++ run
  -> import queue/crashes/hangs/fuzzer_stats
  -> build feedback profile
  -> next template round
```

Outputs include `loop_manifest.json`, per-phase `standard_metrics.json`, and
`loop_standard_metrics.json`.

### 6. AFL++/ASan cups-filters build

For isolated AFL++ and ASan runs, build into `work/` instead of a system prefix.
By default this expects local source trees under `/data/pre-gsoc`; override the
paths with `SMT_AFL_*_SRC` variables when needed.

```bash
scripts/build_afl_cupsfilters_stack.sh
```

Then run a real filter loop, for example:

```bash
bash scripts/run_template_real_afl_loop.sh pwgtopdf 1200 300
```

The build output is written under:

```text
work/afl-src/
work/afl-builds/
work/afl-install/
work/build-afl-cupsfilters/
```

## Outputs

A retained generated case usually contains:

```text
candidate.ppd
document.*
command.txt
meta.json
stderr.txt
stdout.bin
```

Common run outputs:

```text
timeline.jsonl
summary.json
dedup.json
dedup.md
standard_metrics.json
coverage reports, when enabled
```

AFL++ outputs are read from standard AFL++ directories such as `queue/`,
`crashes/`, `hangs/`, and `fuzzer_stats`.

## Metrics

The project records both fuzzing and research metrics:

- executions and execs/sec
- AFL++ bitmap coverage and corpus counts
- retained corpus size and semantic feature count
- features per minute/hour
- crash-candidate counts and deduplicated signatures
- hangs/timeouts/skipped cases
- disk usage
- optional LLVM function/line/branch/region coverage

Crash count alone is not treated as success. A candidate is useful after replay,
deduplication, and source-level triage.

Representative local measurements from clone-local and local-filter runs:

| Run | Result |
| --- | --- |
| 30-minute LLVM metrics run | 193369 executions, 7287 semantic features, 5516 retained cases, 31.68% line coverage, 22.58% branch coverage |
| Standard AFL++ PWG-to-PDF-style run | 659225 executions, 245.81 execs/sec, 5.01% AFL++ bitmap coverage |
| Standard AFL++ PWG-to-PCLm-style run | 1299718 executions, 483.39 execs/sec, 3.86% AFL++ bitmap coverage |

Crash-candidate details and private triage logs should stay out of public pull
requests until they are minimized and reported through the appropriate security
channel.

## Triage

Deduplicate and summarize a run:

```bash
PYTHONPATH=src python3 -m parser_fuzzers.cli dedup-crashes --run-dir <run-dir>
PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics --run-dir <run-dir>
```

Replay a retained case with an ASan-built filter:

```bash
scripts/replay_asan_filter.sh imagetops <case-dir>
scripts/replay_asan_filter.sh imagetoraster <case-dir>
scripts/replay_asan_filter.sh pdftoraster <case-dir>
```

Run a case under GDB:

```bash
scripts/gdb_crash_filter.sh <filter> <case-dir>
```

## Safety And Seed Policy

- Private reproducers are not placed in `seeds/public/`.
- Generated work stays under `work/`, which is ignored by git.
- Large run artifacts should be archived before deletion.
- Public issue reports should include minimized reproducers and upstream replay
  evidence, not raw fuzzing directories.
- The clone-only smoke path should work without private local reports or reproducer
  files.

## Further Reading

- `docs/architecture.md`: layered codebase map and data-flow boundaries
- `src/parser_fuzzers/README.md`: Python package layout
- `scripts/README.md`: script map
- `configs/README.md`: config map
- `docs/evaluation.md`: experiment metrics and oracle semantics
- `docs/coverage-discovery.md`: coverage-discovery mode
- `docs/branch-events.md`: SMT branch-event and patch schemas
- `docs/oss-fuzz-comparison.md`: comparison notes
- `docs/next-stage-evaluation.md`: next evaluation steps
