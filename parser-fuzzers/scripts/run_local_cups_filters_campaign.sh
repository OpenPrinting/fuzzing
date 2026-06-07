#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER_ROOT="${1:-${SMT_FUZZER_FILTER_ROOT:-/usr/lib/cups/filter}}"
DURATION_SEC="${2:-60}"
WORKERS="${3:-4}"
TIMEOUT_SEC="${4:-5}"
CONFIG="${5:-configs/parser_targets_general.yaml}"

cd "$ROOT"
export SMT_FUZZER_FILTER_ROOT="$FILTER_ROOT"
export PYTHONPATH="$ROOT/src"

scripts/check_cups_filters_targets.sh "$FILTER_ROOT"

python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$CONFIG" \
  --work-root work/local-cups-filters \
  --filter-root "$FILTER_ROOT" \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC" \
  --duration-sec "$DURATION_SEC" \
  --discard-stdout \
  --discovery-mode coverage

latest_run="$(ls -dt work/local-cups-filters/* 2>/dev/null | head -n 1 || true)"
if [[ -n "$latest_run" ]]; then
  python3 -m parser_fuzzers.cli dedup-crashes --run-dir "$latest_run"
  scripts/report_campaign_result.sh "$latest_run" "${SMT_FUZZER_ASAN_ROOT:-work/openprinting-asan}"
fi
