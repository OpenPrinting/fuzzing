#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

out="${1:-work/dynamic/libdynamic_compare_trace.so}"
mkdir -p "$(dirname "$out")"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:-}"

"$CC" -O2 -g -fPIC -shared $CFLAGS \
  harnesses/dynamic_compare_trace.c \
  -ldl \
  -o "$out"

echo "$out"
