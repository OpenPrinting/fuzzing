#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-1200}"
WORKERS="${2:-10}"
TIMEOUT_SEC="${3:-5}"
SEED_SKIP_STATE="${4:-}"
FAMILY_SKIP_AFTER="${5:-12}"

cd "$ROOT"
ARGS=(
  --config configs/parser_targets_structural.yaml
  --work-root work/structural-campaign
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --duration-sec "$DURATION_SEC"
  --discard-stdout
  --discovery-mode coverage
  --scheduler novelty
  --runtime-skip
  --generalized-skip
  --family-skip-after "$FAMILY_SKIP_AFTER"
  --prune-uninteresting
)

if [[ -n "$SEED_SKIP_STATE" ]]; then
  ARGS+=(--seed-skip-state "$SEED_SKIP_STATE")
fi

PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
