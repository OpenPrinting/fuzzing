#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-300}"
WORKERS="${2:-4}"
TIMEOUT_SEC="${3:-5}"
SEED_SKIP_STATE="${4:-}"
FAMILY_SKIP_AFTER="${5:-}"

cd "$ROOT"
ARGS=(
  --config configs/parser_targets_coverage.yaml
  --work-root work/deep-coverage
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --duration-sec "$DURATION_SEC"
  --discard-stdout
  --discovery-mode coverage
  --scheduler novelty
  --runtime-skip
  --prune-uninteresting
)

if [[ -n "$SEED_SKIP_STATE" ]]; then
  ARGS+=(--seed-skip-state "$SEED_SKIP_STATE")
fi
if [[ -n "$FAMILY_SKIP_AFTER" ]]; then
  ARGS+=(--generalized-skip --family-skip-after "$FAMILY_SKIP_AFTER")
fi

PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
