#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER="${1:-}"
CASE_DIR="${2:-}"
OUT_DIR="${3:-}"

if [[ -z "$FILTER" || -z "$CASE_DIR" ]]; then
  echo "usage: $0 <filter|/path/to/filter> <case-dir> [out-dir]" >&2
  exit 2
fi

if [[ "$FILTER" = /* ]]; then
  FILTER_BIN="$FILTER"
  FILTER_NAME="$(basename "$FILTER")"
else
  FILTER_NAME="$FILTER"
  FILTER_ROOT="${SMT_FUZZER_FILTER_ROOT:-$ROOT/work/openprinting-asan/src/cups-filters}"
  FILTER_BIN="$FILTER_ROOT/$FILTER_NAME"
fi

CASE_DIR="$(cd "$CASE_DIR" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/work/asan-replay/$(basename "$CASE_DIR")-$FILTER_NAME}"
mkdir -p "$OUT_DIR"

PPD_FILE="$CASE_DIR/candidate.ppd"
if [[ ! -f "$PPD_FILE" ]]; then
  echo "missing PPD: $PPD_FILE" >&2
  exit 2
fi

DOC_FILE=""
for candidate in \
  "$CASE_DIR"/document.pwg \
  "$CASE_DIR"/document.ras \
  "$CASE_DIR"/document.pdf \
  "$CASE_DIR"/document.ps \
  "$CASE_DIR"/document.txt \
  "$CASE_DIR"/document.ppm \
  "$CASE_DIR"/document.pgm \
  "$CASE_DIR"/document.pbm \
  "$CASE_DIR"/document.png \
  "$CASE_DIR"/document.cmd \
  "$CASE_DIR"/document.bin; do
  if [[ -f "$candidate" ]]; then
    DOC_FILE="$candidate"
    break
  fi
done

if [[ -z "$DOC_FILE" ]]; then
  echo "missing document input in $CASE_DIR" >&2
  exit 2
fi

if [[ ! -x "$FILTER_BIN" ]]; then
  echo "missing executable filter: $FILTER_BIN" >&2
  exit 2
fi

ASAN_ROOT="${SMT_FUZZER_ASAN_ROOT:-$ROOT/work/openprinting-asan}"
LIBCUPSFILTERS_ASAN="${LIBCUPSFILTERS_ASAN:-$ASAN_ROOT/src/libcupsfilters/.libs}"
LIBPPD_ASAN="${LIBPPD_ASAN:-$ASAN_ROOT/src/libppd/.libs}"
PREFIX_LIB="${PREFIX_LIB:-$ASAN_ROOT/prefix/lib}"
PREFIX_LIB_DIR_64="${PREFIX_LIB_DIR_64:-$ASAN_ROOT/prefix/lib64}"
LD_LIBRARY_PATH_VALUE="${SMT_FUZZER_LD_LIBRARY_PATH:-$LIBCUPSFILTERS_ASAN:$LIBPPD_ASAN:$PREFIX_LIB:$PREFIX_LIB_DIR_64}:${LD_LIBRARY_PATH:-}"
ASAN_OPTIONS_VALUE="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=1}"

cat > "$OUT_DIR/replay.env" <<EOF
FILTER_BIN=$FILTER_BIN
PPD=$PPD_FILE
DOC=$DOC_FILE
LD_LIBRARY_PATH=$LD_LIBRARY_PATH_VALUE
ASAN_OPTIONS=$ASAN_OPTIONS_VALUE
EOF

set +e
env \
  LD_LIBRARY_PATH="$LD_LIBRARY_PATH_VALUE" \
  ASAN_OPTIONS="$ASAN_OPTIONS_VALUE" \
  PPD="$PPD_FILE" \
  "$FILTER_BIN" 1 smt smt 1 "" "$DOC_FILE" \
  > "$OUT_DIR/stdout.txt" \
  2> "$OUT_DIR/asan.txt"
status=$?
set -e

{
  echo "status=$status"
  echo "filter=$FILTER_BIN"
  echo "ppd=$PPD_FILE"
  echo "document=$DOC_FILE"
  echo "stdout=$OUT_DIR/stdout.txt"
  echo "asan=$OUT_DIR/asan.txt"
} > "$OUT_DIR/summary.txt"

cat "$OUT_DIR/summary.txt"
exit "$status"
