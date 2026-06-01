#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-300}"
WORKERS="${2:-4}"
TIMEOUT_SEC="${3:-5}"

cd "$ROOT"
PYTHONPATH=src python3 -m smt_fuzzer.cli multitarget-monitor \
  --config configs/parser_targets_coverage.yaml \
  --work-root work/deep-coverage \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC" \
  --duration-sec "$DURATION_SEC" \
  --discard-stdout \
  --discovery-mode coverage
