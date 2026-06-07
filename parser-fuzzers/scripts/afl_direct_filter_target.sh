#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <input-document>" >&2
  exit 2
fi

input_document="$1"
filter_binary="${SMT_AFL_DIRECT_FILTER_BINARY:-${AFL_DIRECT_FILTER_BINARY:-}}"
ppd_path="${SMT_AFL_DIRECT_PPD:-${AFL_DIRECT_PPD:-}}"
job_options="${SMT_AFL_DIRECT_JOB_OPTIONS:-${AFL_DIRECT_JOB_OPTIONS:-}}"

if [[ -z "$filter_binary" || -z "$ppd_path" ]]; then
  echo "SMT_AFL_DIRECT_FILTER_BINARY and SMT_AFL_DIRECT_PPD must be set" >&2
  exit 2
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/smt-afl-direct.XXXXXX")"
stderr_file="$tmpdir/stderr.txt"
stdout_file="$tmpdir/stdout.bin"

cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

export PPD="$ppd_path"
direct_ld_library_path="${SMT_AFL_DIRECT_LD_LIBRARY_PATH:-${AFL_DIRECT_LD_LIBRARY_PATH:-}}"
if [[ -n "$direct_ld_library_path" ]]; then
  export LD_LIBRARY_PATH="$direct_ld_library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=0}"

set +e
"$filter_binary" 1 afl afl 1 "$job_options" "$input_document" >"$stdout_file" 2>"$stderr_file"
status="$?"
set -e

if [[ "$status" == "86" ]]; then
  cat "$stderr_file" >&2
  exit 86
fi

if (( status >= 128 )); then
  cat "$stderr_file" >&2
  exit 86
fi

if grep -Eq "AddressSanitizer|UndefinedBehaviorSanitizer|ERROR: LeakSanitizer|runtime error:" "$stderr_file"; then
  cat "$stderr_file" >&2
  exit 86
fi

exit 0
