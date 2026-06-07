#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASES_PER_TARGET="${1:-1}"
WORKERS="${2:-4}"

cd "$ROOT"
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config configs/parser_targets.yaml \
  --work-root work/multitarget \
  --workers "$WORKERS" \
  --cases-per-target "$CASES_PER_TARGET"
