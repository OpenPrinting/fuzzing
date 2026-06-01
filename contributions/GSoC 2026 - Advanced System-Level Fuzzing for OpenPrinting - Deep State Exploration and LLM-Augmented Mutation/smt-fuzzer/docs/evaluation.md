# Evaluation Plan

The project tracks four goals:

- `G1`: general source and edge coverage improvement.
- `G2`: target parser/filter-option coverage improvement.
- `G3`: crash discovery and sanitizer-signal quality improvement.
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

Use `python3 -m smt_fuzzer.cli afl-prepare` to materialize an AFL++ run
without launching it. This command merges the per-target dictionaries into one
AFL++ dictionary, prepares `work/afl/input/<target>/<config>`, imports
`work/corpus/smt` for `A4`, and prints the exact `afl-fuzz` command.

`python3 -m smt_fuzzer.cli afl-run ... --execute` is the only command that
starts AFL++. It checks that `afl-fuzz` and the target binary exist before
launching.

## Metrics

- line/function/branch coverage from a neutral coverage binary.
- target function and target branch coverage.
- time to first unique crash signature.
- retained corpus growth and feature novelty over time.
- solver attempts, sat/unsat/timeout, solver time, patched fields.
- SMT coverage yield: solver inputs with new coverage / solver inputs.
- SMT crash yield: solver inputs producing unique crash signatures / solver inputs.
- cost per new edge: total solver time / new edges from solver inputs.

The first smoke run can be `5 repetitions x 6h`. A stronger internal run should
use `10 repetitions x 24h`.
