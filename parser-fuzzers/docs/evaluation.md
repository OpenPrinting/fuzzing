# Evaluation Plan

The project tracks four goals:

- `G1`: general source and edge coverage improvement.
- `G2`: target parser/filter-option coverage improvement.
- `G3`: known bug reached/triggered/detected improvement.
- `G4`: measurable SMT contribution.

## Experiment Matrix

- `A0`: vanilla.
- `A1`: dictionary.
- `A2`: dictionary + CmpLog.
- `A3`: dictionary + grammar/custom mutator.
- `A4`: dictionary + grammar/custom mutator + SMT patcher.

Use the same seeds, resource limits, target binaries, and coverage replay
binary across all configurations.

## AFL++ Integration

`configs/afl.yaml` controls AFL++ defaults:

- fuzzer and compiler wrapper names.
- weak seed directory.
- SMT corpus import directory.
- AFL++ work/output directories.
- timeout and memory limit.
- optional custom mutator library.

Use `python3 -m parser_fuzzers.cli afl-prepare` to materialize an AFL++ run
without launching it. This command merges the per-target dictionaries into one
AFL++ dictionary, prepares `work/afl/input/<target>/<config>`, imports
`work/corpus/smt` for `A4`, and prints the exact `afl-fuzz` command.

`python3 -m parser_fuzzers.cli afl-run ... --execute` is the only command that
starts AFL++. It checks that `afl-fuzz` and the target binary exist before
launching.

## Metrics

- line/function/branch coverage from a neutral coverage binary.
- target function and target branch coverage.
- reached/triggered/detected time for every known bug.
- solver attempts, sat/unsat/timeout, solver time, patched fields.
- SMT coverage yield: solver inputs with new coverage / solver inputs.
- SMT bug yield: solver inputs triggering bugs / solver inputs.
- cost per new edge: total solver time / new edges from solver inputs.

Use `python3 -m parser_fuzzers.cli summarize-run-metrics --run-dir <run-dir>`
to generate the common per-run JSON metrics payload. It can also attach AFL++
`fuzzer_stats` and LLVM `coverage.json` data.

The first smoke run can be `5 repetitions x 6h`. A stronger internal run should
use `10 repetitions x 24h`.

See `docs/next-stage-evaluation.md` for coverage, historical-reproducer, and
target-expansion policy.
