#!/bin/bash -eu

# build and install pyppd
cd $SRC/pyppd
pip3 install .

# compile all fuzzers with seeds
for fuzzer in $(find $SRC/fuzzing/projects/pyppd/fuzzer -name 'fuzz_*.py'); do
  fuzzer_name=$(basename "$fuzzer" .py)
  
  seed_dir="$SRC/fuzzing/projects/pyppd/seeds/$fuzzer_name"
  if [ -d "$seed_dir" ]; then
    cd "$seed_dir" && zip -r "$OUT/${fuzzer_name}_seed_corpus.zip" .
  fi
  
  compile_python_fuzzer "$fuzzer" --add-data "$SRC/pyppd:pyppd"
done
