# AFL++ Workflow

This project treats AFL++ as the main driver for CLI/forkserver fuzzing.

## Build Environment

Print the recommended compiler environment:

```bash
scripts/afl_build_env.sh
```

For an ASan/UBSan AFL++ target, build with:

```bash
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
export CXXFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address,undefined"
```

## Run Planning

Generate a dry-run command:

```bash
scripts/run_afl.sh ppd_ipp_parser A1 harnesses/bin/ppd_ipp_parser
```

Launch only when the instrumented binary exists and AFL++ is installed:

```bash
scripts/run_afl.sh ppd_ipp_parser A1 harnesses/bin/ppd_ipp_parser --execute
```

## Config Mapping

- `A0`: weak seeds only.
- `A1`: weak seeds plus merged target dictionary.
- `A2`: `A1` plus `-c <binary>.cmplog`.
- `A3`: `A1` plus `AFL_CUSTOM_MUTATOR_LIBRARY` when configured.
- `A4`: `A3` plus SMT candidates imported from `work/corpus/smt`.

The submitted seed directories contain only weak public seeds and generated
SMT corpus candidates.
