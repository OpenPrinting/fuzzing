#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER="${1:-}"
CASE_DIR="${2:-}"
BREAKPOINT="${3:-}"
OUT_DIR="${4:-}"

if [[ -z "$FILTER" || -z "$CASE_DIR" ]]; then
  echo "usage: $0 <filter|/path/to/filter> <case-dir> [breakpoint] [out-dir]" >&2
  echo "example: $0 pwgtoraster work/arithmetic-explore/<run>/cases/case-000001 cupsfilters/pwgtoraster.c:1906" >&2
  exit 2
fi

if [[ "$FILTER" = /* ]]; then
  FILTER_BIN="$FILTER"
  FILTER_NAME="$(basename "$FILTER")"
else
  FILTER_NAME="$FILTER"
  FILTER_BIN="/data/pre-gsoc/cups-filters/$FILTER_NAME"
fi

CASE_DIR="$(cd "$CASE_DIR" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/work/asan-replay/$(basename "$CASE_DIR")-$FILTER_NAME-gdb}"
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

LIBPPD_ASAN="${LIBPPD_ASAN:-${SMT_FUZZER_LIBPPD_ASAN:-/data/pre-gsoc/libppd-origin-latest/.libs}}"
LIBCUPSFILTERS_ASAN="${LIBCUPSFILTERS_ASAN:-${SMT_FUZZER_LIBCUPSFILTERS_ASAN:-/data/pre-gsoc/libcupsfilters-master-asan/.libs}}"
if [[ ! -d "$LIBCUPSFILTERS_ASAN" ]]; then
  LIBCUPSFILTERS_ASAN="/data/pre-gsoc/libcupsfilters/.libs"
fi
PDFIO_LIB="${PDFIO_LIB:-${SMT_FUZZER_PDFIO_LIB:-/data/pre-gsoc/env/pdfio-install/lib}}"
LD_LIBRARY_PATH_VALUE="$LIBPPD_ASAN:$LIBCUPSFILTERS_ASAN:$PDFIO_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ASAN_OPTIONS_VALUE="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=1}"

GDB_ARGS=(
  --batch
  -ex "set debuginfod enabled off"
  -ex "set breakpoint pending on"
  -ex "set env LD_LIBRARY_PATH=$LD_LIBRARY_PATH_VALUE"
  -ex "set env ASAN_OPTIONS=$ASAN_OPTIONS_VALUE"
  -ex "set env PPD=$PPD_FILE"
)

if [[ -n "$BREAKPOINT" ]]; then
  GDB_ARGS+=(-ex "break $BREAKPOINT")
fi

GDB_ARGS+=(
  -ex "run"
  -ex "bt full"
  -ex "frame 0"
  -ex "info locals"
  --args "$FILTER_BIN" 1 smt smt 1 "" "$DOC_FILE"
)

set +e
gdb "${GDB_ARGS[@]}" > "$OUT_DIR/gdb.txt" 2>&1
status=$?
set -e

{
  echo "status=$status"
  echo "filter=$FILTER_BIN"
  echo "ppd=$PPD_FILE"
  echo "document=$DOC_FILE"
  echo "breakpoint=${BREAKPOINT:-<none>}"
  echo "gdb=$OUT_DIR/gdb.txt"
} > "$OUT_DIR/summary.txt"

cat "$OUT_DIR/summary.txt"
exit "$status"
