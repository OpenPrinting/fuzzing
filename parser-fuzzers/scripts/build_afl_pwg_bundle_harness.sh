#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f work/afl-install/afl-env.sh ]]; then
  bash scripts/build_afl_cupsfilters_stack.sh
fi
source work/afl-install/afl-env.sh

out="${1:-work/afl/bin/pwg_bundle_harness}"
mkdir -p "$(dirname "$out")"

CC="${CC:-afl-clang-fast}"
CFLAGS="${CFLAGS:-}"
if [[ "${SMT_AFL_BUNDLE_CMPLOG:-0}" == "1" ]]; then
  export AFL_LLVM_CMPLOG=1
else
  unset AFL_LLVM_CMPLOG
fi

"$CC" -O1 -g -fno-omit-frame-pointer -fsanitize=address $CFLAGS \
  -Iwork/afl-src/libcupsfilters \
  -Iwork/afl-src/libppd \
  -Iwork/afl-install/libppd/include \
  harnesses/afl_pwg_bundle_harness.c \
  -L"$SMT_AFL_LIBCUPSFILTERS_LIB" -Wl,-rpath,"$SMT_AFL_LIBCUPSFILTERS_LIB" -lcupsfilters \
  -L"$SMT_AFL_LIBPPD_LIB" -Wl,-rpath,"$SMT_AFL_LIBPPD_LIB" -lppd \
  -L"$SMT_AFL_PDFIO_LIB" -Wl,-rpath,"$SMT_AFL_PDFIO_LIB" \
  -o "$out"

echo "$out"
