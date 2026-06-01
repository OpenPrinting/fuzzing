# Harness Notes

This directory holds interface templates, not production CUPS harnesses.

The first implementation target is the Python-side SMT data flow:

1. a harness or tracer emits a branch-event JSON file;
2. `solve-event` emits a solver-result JSON file;
3. `patch-input` creates a candidate input in `work/corpus/smt`;
4. AFL++/libFuzzer imports or replays that candidate.

Future CUPS harnesses should keep the initial corpus weak and generic, then
import generated SMT candidates only through documented corpus directories.
