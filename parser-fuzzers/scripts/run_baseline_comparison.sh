#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION_SEC="${1:-60}"
WORKERS="${2:-4}"
TIMEOUT_SEC="${3:-5}"
CONFIG="${SMT_FUZZER_COMPARE_CONFIG:-work/parser_targets_cold_semantic_llvm.yaml}"
OSS_FUZZ_DIR="${SMT_FUZZER_OSS_FUZZ_DIR:-/data/pre-gsoc/oss-fuzz}"
WORK_ROOT="${SMT_FUZZER_COMPARE_WORK_ROOT:-work/baseline-comparison}"
MAX_RUN_GB="${SMT_FUZZER_COMPARE_MAX_GB:-10}"
OPTIMIZED_POLICY="${SMT_FUZZER_COMPARE_POLICY:-avoidance}"

if [[ ! -f "$CONFIG" ]]; then
  echo "missing config: $CONFIG" >&2
  echo "build coverage filters first, or set SMT_FUZZER_COMPARE_CONFIG=configs/parser_targets_cold_semantic.yaml" >&2
  exit 2
fi

LLVM_ARGS=()
if command -v llvm-profdata-18 >/dev/null 2>&1 || command -v llvm-profdata >/dev/null 2>&1; then
  if command -v llvm-cov-18 >/dev/null 2>&1 || command -v llvm-cov >/dev/null 2>&1; then
    LLVM_ARGS=(--enable-llvm-profiles --export-llvm-coverage)
  fi
fi

PYTHONPATH=src python3 -m parser_fuzzers.cli compare-baseline-metrics \
  --config "$CONFIG" \
  --work-root "$WORK_ROOT" \
  --oss-fuzz-dir "$OSS_FUZZ_DIR" \
  --duration-sec "$DURATION_SEC" \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC" \
  --max-run-gb "$MAX_RUN_GB" \
  --optimized-policy "$OPTIMIZED_POLICY" \
  "${LLVM_ARGS[@]}"
