# smt-fuzzer

Discovery-oriented SMT and format-aware fuzzing skeleton for OpenPrinting
CUPS/cups-filters targets.

The public snapshot is intentionally generic: it contains weak seeds,
format-aware generators, target runners, AFL++ interfaces, and crash
deduplication. Issue-specific regression drivers and private reproduction
material are not part of this tree.

## Data Flow

```text
                  +-------------------+
input bytes ----> | branch event JSON | ----+
                  +-------------------+     |
                                            v
                                      +-----------+
                                      | Z3 solver |
                                      +-----------+
                                            |
                                            v
                  +-------------------+  patches  +----------------+
seed/candidate -> | patch-input       | --------> | work/corpus/smt |
                  +-------------------+           +----------------+

PPD template + document template
              |
              v
        +-------------+        stderr/meta        +-------------+
        | CUPS filter | ------------------------> | crash dedup |
        +-------------+                           +-------------+
              |
              v
        work/<campaign>/<run-id>/
```

## Repository Map

```text
smt-fuzzer/
|-- src/smt_fuzzer/       Python CLI and runners
|-- configs/              parser targets, AFL++, A0-A4 matrix
|-- dictionaries/         generic format dictionaries
|-- docs/                 setup, coverage, evaluation notes
|-- harnesses/            C/C++ interface examples
|-- scripts/              smoke, ASan, AFL++, replay helpers
|-- seeds/public/         weak public seeds
`-- work/                 generated outputs
```

## 0. Setup TUI

For a guided local setup, run:

```bash
scripts/setup_tui.sh
```

The TUI saves local choices to `work/setup.env` and provides menu entries for
dependency installation, Python setup, quick target campaigns, ASan build-plan
generation, and AFL++ command checks.

Non-interactive helpers:

```bash
scripts/setup_tui.sh --status
scripts/setup_tui.sh --commands
```

## 1. Clone-Only Smoke

No CUPS build, AFL++, or target binaries are required.

```bash
scripts/install_ubuntu_deps.sh --minimal -y

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .

scripts/check_env.sh
python3 -m smt_fuzzer.cli validate --configs configs
scripts/run_smoke.sh
python3 -m unittest discover -s tests
```

Expected:

- config validation exits with `{"errors": 0, "warnings": 0}`;
- smoke solves a synthetic branch event and writes a patched input;
- unit tests pass without local OpenPrinting builds.

Use strict Z3 mode when needed:

```bash
SMT_FUZZER_STRICT_Z3=1 scripts/run_smoke.sh
```

## 2. Recommended Quick Target Test

This is the recommended fast target test when CUPS filters are already
installed on the machine. It checks the real PPD+document runner, target
execution, crash collection, and crash deduplication.

```bash
scripts/install_ubuntu_deps.sh --system-filters -y
scripts/check_cups_filters_targets.sh
scripts/run_local_cups_filters_campaign.sh /usr/lib/cups/filter 1 2 5 configs/parser_targets.yaml
```

Command fields:

```text
run_local_cups_filters_campaign.sh <filter-root> <duration-sec> <workers> <timeout-sec> <config>
```

In the development environment, this 1-second smoke reached all configured
targets, generated valid PPDs, and produced deduplicated crash clusters. Results
depend on the locally installed cups-filters version, so use this as a quick
pipeline test; use the isolated ASan workflow below for issue-quality triage.
When crash-classified cases appear, the command prints a short crash summary,
representative case path, and replay/GDB follow-up commands.
On an interactive terminal, `ok`, `crash`, `warning`, and sanitizer lines are
color-highlighted. ASan/UBSan excerpts are printed directly when the
representative stderr contains sanitizer output.

If filters live outside `/usr/lib/cups/filter`:

```bash
export SMT_FUZZER_FILTER_ROOT=/path/to/cups/filter
scripts/check_cups_filters_targets.sh "$SMT_FUZZER_FILTER_ROOT"
scripts/run_local_cups_filters_campaign.sh "$SMT_FUZZER_FILTER_ROOT" 1 2 5 configs/parser_targets.yaml
```

## 3. Recommended ASan Workflow

Crash reports should come from an isolated ASan build. The default layout keeps
all source, build, and install artifacts inside `work/openprinting-asan/`.

```text
work/openprinting-asan/
|-- src/
|   |-- libcupsfilters/
|   |-- libppd/
|   `-- cups-filters/
`-- prefix/
    |-- lib/
    `-- lib64/
```

Print the build plan:

```bash
scripts/install_ubuntu_deps.sh --asan-build -y
scripts/print_cups_filters_build_plan.sh
```

The generated plan uses `clang`, ASan/UBSan flags, and an isolated prefix. It
refuses `/usr`, `/usr/local`, and `/opt` prefixes by default.

After running the printed build commands:

```bash
scripts/run_asan_cups_filters_campaign.sh work/openprinting-asan 60 4 5
```

Run the expanded 20-target profile:

```bash
scripts/run_asan_cups_filters_campaign.sh work/openprinting-asan 300 4 5 configs/parser_targets_coverage.yaml
```

## 4. AFL++ Interface

Print the AFL++ build environment:

```bash
scripts/install_ubuntu_deps.sh --afl -y
scripts/afl_build_env.sh
```

Prepare a dry-run command:

```bash
scripts/run_afl.sh ppd_ipp_parser A1 harnesses/bin/ppd_ipp_parser
```

Launch only when AFL++ and the instrumented binary exist:

```bash
scripts/run_afl.sh ppd_ipp_parser A1 harnesses/bin/ppd_ipp_parser --execute
```

## Outputs

Campaigns write timestamped run directories:

```text
work/<campaign>/<run-id>/
|-- run_manifest.json
|-- commands.txt
|-- timeline.jsonl
|-- summary.json
|-- summary.concise.json
|-- crash_dedup.json
|-- crash_dedup.md
`-- <target-id>/case-0000/
    |-- candidate.ppd
    |-- document.*
    |-- stderr.txt
    |-- stdout.bin
    `-- meta.json
```

Replay a case under the local ASan build:

```bash
scripts/replay_asan_filter.sh pwgtoraster work/<campaign>/<run-id>/<target>/case-0000
```

Collect a GDB backtrace:

```bash
scripts/gdb_crash_filter.sh pwgtoraster work/<campaign>/<run-id>/<target>/case-0000
```

## Useful Docs

- `docs/local-cups-filters.md`: isolated ASan build and campaign workflow.
- `docs/coverage-discovery.md`: feature retention and crash quarantine.
- `docs/expanded-parser-support.md`: current parser/filter target set.
- `docs/branch-events.md`: SMT branch-event and solver-result schemas.
- `docs/evaluation.md`: experiment matrix and metrics.
- `docs/afl-plus-plus.md`: AFL++ command generation.
