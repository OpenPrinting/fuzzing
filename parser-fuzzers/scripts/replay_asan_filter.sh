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
  FILTER_BIN="/data/pre-gsoc/cups-filters/$FILTER_NAME"
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

LIBPPD_ASAN="${LIBPPD_ASAN:-${SMT_FUZZER_LIBPPD_ASAN:-/data/pre-gsoc/libppd-origin-latest/.libs}}"
LIBCUPSFILTERS_ASAN="${LIBCUPSFILTERS_ASAN:-${SMT_FUZZER_LIBCUPSFILTERS_ASAN:-/data/pre-gsoc/libcupsfilters-master-asan/.libs}}"
if [[ ! -d "$LIBCUPSFILTERS_ASAN" ]]; then
  LIBCUPSFILTERS_ASAN="/data/pre-gsoc/libcupsfilters/.libs"
fi
PDFIO_LIB="${PDFIO_LIB:-${SMT_FUZZER_PDFIO_LIB:-/data/pre-gsoc/env/pdfio-install/lib}}"
LD_LIBRARY_PATH_VALUE="$LIBPPD_ASAN:$LIBCUPSFILTERS_ASAN:$PDFIO_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
ASAN_OPTIONS_VALUE="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86}"
JOB_OPTIONS="${SMT_FUZZER_REPLAY_JOB_OPTIONS:-}"

if [[ -z "$JOB_OPTIONS" && -f "$CASE_DIR/meta.json" ]]; then
  JOB_OPTIONS="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("job_options", ""))' "$CASE_DIR/meta.json")"
fi

if [[ -z "$JOB_OPTIONS" && -f "$CASE_DIR/command.txt" ]]; then
  JOB_OPTIONS="$(python3 -c 'import shlex, sys
parts = shlex.split(open(sys.argv[1], encoding="utf-8").read())
while parts and "=" in parts[0] and parts[0].split("=", 1)[0].replace("_", "").isalnum():
    parts.pop(0)
print(parts[-2] if len(parts) >= 6 else "")' "$CASE_DIR/command.txt")"
fi

cat > "$OUT_DIR/replay.env" <<EOF
FILTER_BIN=$FILTER_BIN
PPD=$PPD_FILE
DOC=$DOC_FILE
JOB_OPTIONS=$JOB_OPTIONS
LD_LIBRARY_PATH=$LD_LIBRARY_PATH_VALUE
ASAN_OPTIONS=$ASAN_OPTIONS_VALUE
EOF

set +e
env \
  LD_LIBRARY_PATH="$LD_LIBRARY_PATH_VALUE" \
  ASAN_OPTIONS="$ASAN_OPTIONS_VALUE" \
  PPD="$PPD_FILE" \
  "$FILTER_BIN" 1 smt smt 1 "$JOB_OPTIONS" "$DOC_FILE" \
  > "$OUT_DIR/stdout.txt" \
  2> "$OUT_DIR/asan.txt"
status=$?
set -e

{
  echo "status=$status"
  echo "filter=$FILTER_BIN"
  echo "ppd=$PPD_FILE"
  echo "document=$DOC_FILE"
  echo "job_options=$JOB_OPTIONS"
  echo "stdout=$OUT_DIR/stdout.txt"
  echo "asan=$OUT_DIR/asan.txt"
} > "$OUT_DIR/summary.txt"

cat "$OUT_DIR/summary.txt"
exit "$status"
