#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-600}"
WORKERS="${2:-4}"
TIMEOUT_SEC="${3:-5}"

cd "$ROOT"
PYTHONPATH=src python3 -m parser_fuzzers.cli arithmetic-explore \
  --work-dir work/arithmetic-explore \
  --duration-sec "$DURATION_SEC" \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC"
