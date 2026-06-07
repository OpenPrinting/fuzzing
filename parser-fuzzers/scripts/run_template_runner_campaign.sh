#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION_SEC="${1:-${SMT_TEMPLATE_DURATION:-60}}"
WORKERS="${2:-${SMT_TEMPLATE_WORKERS:-2}}"
TIMEOUT_SEC="${3:-${SMT_TEMPLATE_TIMEOUT_SEC:-5}}"
CONFIG="${4:-${SMT_TEMPLATE_CONFIG:-configs/parser_targets_auto_hybrid.yaml}}"
WORK_ROOT="${SMT_TEMPLATE_WORK_ROOT:-work/template-runner}"
MAX_RUN_GB="${SMT_TEMPLATE_MAX_RUN_GB:-1}"
FILTER_ROOT="${SMT_TEMPLATE_FILTER_ROOT:-${SMT_FUZZER_TEMPLATE_FILTER_ROOT:-${SMT_FUZZER_FILTER_ROOT:-/data/pre-gsoc/cups-filters}}}"

prompt_filter_root() {
  local answer
  if [[ "${SMT_TEMPLATE_SKIP_FILTER_PROMPT:-0}" == "1" ]]; then
    return
  fi
  if [[ -t 0 ]]; then
    printf 'Template runner filter root [%s]: ' "$FILTER_ROOT"
    read -r answer
    if [[ -n "$answer" ]]; then
      FILTER_ROOT="$answer"
    fi
  fi
}

prompt_filter_root

if [[ ! -d "$FILTER_ROOT" ]]; then
  echo "missing template filter root: $FILTER_ROOT" >&2
  echo "set SMT_TEMPLATE_FILTER_ROOT or enter a directory containing cups-filters binaries" >&2
  exit 2
fi

if [[ "${SMT_TEMPLATE_CHECK_FILTERS:-1}" != "0" ]]; then
  scripts/check_cups_filters_targets.sh --coverage "$FILTER_ROOT"
fi

export PYTHONPATH="$ROOT/src"
python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$CONFIG" \
  --work-root "$WORK_ROOT" \
  --filter-root "$FILTER_ROOT" \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC" \
  --duration-sec "$DURATION_SEC" \
  --max-run-gb "$MAX_RUN_GB" \
  --discard-stdout \
  --discovery-mode coverage \
  --scheduler novelty \
  --runtime-skip \
  --summary-mode concise \
  --prune-uninteresting
