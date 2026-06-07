#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <profraw-dir> <binary> <out-dir>" >&2
  exit 2
fi

PROFRAW_DIR="$1"
BINARY="$2"
OUT_DIR="$3"
mkdir -p "$OUT_DIR"

if ! command -v llvm-profdata >/dev/null 2>&1; then
  echo "missing llvm-profdata in PATH" >&2
  exit 2
fi
if ! command -v llvm-cov >/dev/null 2>&1; then
  echo "missing llvm-cov in PATH" >&2
  exit 2
fi

llvm-profdata merge -sparse "$PROFRAW_DIR"/*.profraw -o "$OUT_DIR/coverage.profdata"
llvm-cov export "$BINARY" -instr-profile="$OUT_DIR/coverage.profdata" > "$OUT_DIR/coverage.json"
llvm-cov report "$BINARY" -instr-profile="$OUT_DIR/coverage.profdata" > "$OUT_DIR/coverage.txt"

echo "$OUT_DIR/coverage.json"
echo "$OUT_DIR/coverage.txt"
