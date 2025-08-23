#!/bin/bash -eu

# build and install pycups
cd $SRC/pycups
pip3 install .

# compile all fuzzers
for fuzzer in $(find $SRC/fuzzing/projects/pycups/fuzzer -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer --hidden-import=cffi
done