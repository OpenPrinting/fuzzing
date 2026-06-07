#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASAN_ROOT="${1:-$ROOT/work/openprinting-asan}"
DURATION_SEC="${2:-60}"
WORKERS="${3:-4}"
TIMEOUT_SEC="${4:-5}"
CONFIG="${5:-configs/parser_targets_general.yaml}"

PREFIX="$ASAN_ROOT/prefix"
SRC_ROOT="$ASAN_ROOT/src"
FILTER_ROOT="$SRC_ROOT/cups-filters"
LIB_PATHS="$SRC_ROOT/libcupsfilters/.libs:$SRC_ROOT/libppd/.libs:$PREFIX/lib:$PREFIX/lib64"

case "$ASAN_ROOT" in
  /|/usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*)
    echo "refusing non-isolated ASan root: $ASAN_ROOT" >&2
    exit 2
    ;;
esac

if [[ ! -d "$FILTER_ROOT" ]]; then
  echo "missing local ASan cups-filters tree: $FILTER_ROOT" >&2
  echo "print a build plan with: scripts/print_cups_filters_build_plan.sh $ASAN_ROOT" >&2
  exit 2
fi

cd "$ROOT"
export SMT_FUZZER_FILTER_ROOT="$FILTER_ROOT"
export SMT_FUZZER_LD_LIBRARY_PATH="$LIB_PATHS"
export SMT_FUZZER_ASSUME_ASAN=1
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86}"
export PYTHONPATH="$ROOT/src"

scripts/check_cups_filters_targets.sh "$SMT_FUZZER_FILTER_ROOT"
scripts/run_local_cups_filters_campaign.sh "$SMT_FUZZER_FILTER_ROOT" "$DURATION_SEC" "$WORKERS" "$TIMEOUT_SEC" "$CONFIG"
