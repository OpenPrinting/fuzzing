#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASES_PER_TARGET="${1:-}"
WORKERS="${2:-4}"

cd "$ROOT"
cmd=(
  python3 -m parser_fuzzers.cli multitarget-monitor
  --config configs/parser_targets_explore.yaml
  --work-root work/explore
  --workers "$WORKERS"
)
if [[ -n "$CASES_PER_TARGET" ]]; then
  cmd+=(--cases-per-target "$CASES_PER_TARGET")
fi

PYTHONPATH=src "${cmd[@]}"
