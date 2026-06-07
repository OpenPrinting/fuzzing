#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$#" -lt 3 ]]; then
  echo "usage: $0 <target-id> <A0-A4|name> <afl-instrumented-binary> [--execute]"
  exit 2
fi

target="$1"
config="$2"
binary="$3"
shift 3

export PYTHONPATH="$ROOT/src"
python3 -m parser_fuzzers.cli afl-run \
  --root "$ROOT" \
  --configs configs \
  --target "$target" \
  --config "$config" \
  --binary "$binary" \
  "$@"
