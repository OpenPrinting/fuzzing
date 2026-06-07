#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

out="${1:-work/afl/bin/template_probe}"
mkdir -p "$(dirname "$out")"

afl-clang-fast -O1 -g -fno-omit-frame-pointer \
  -o "$out" \
  harnesses/afl_template_probe.c

echo "$out"
