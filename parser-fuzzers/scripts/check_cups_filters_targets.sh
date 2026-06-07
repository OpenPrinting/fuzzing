#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="minimal"

if [[ "${1:-}" == "--coverage" ]]; then
  mode="coverage"
  shift
fi

FILTER_ROOT="${1:-${SMT_FUZZER_FILTER_ROOT:-/usr/lib/cups/filter}}"
missing=0

check_cmd() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    echo "[ok] $name: $(command -v "$name")"
  else
    echo "[missing] $name"
    missing=1
  fi
}

check_filter() {
  local name="$1"
  local path="$FILTER_ROOT/$name"
  if [[ -x "$path" ]]; then
    echo "[ok] $name: $path"
  else
    echo "[missing] $name: $path"
    missing=1
  fi
}

minimal_filters=(
  rastertopclx
  rastertoescpx
  pwgtoraster
)

coverage_filters=(
  rastertopclx
  rastertoescpx
  rastertops
  pwgtoraster
  pwgtopdf
  pdftopdf
  pdftops
  pdftoraster
  mupdftopwg
  imagetoraster
  imagetopdf
  imagetops
  texttopdf
  texttotext
  gstoraster
  gstopdf
  gstopxl
  pwgtopclm
  commandtoescpx
  commandtopclx
)

echo "[info] project: $ROOT"
echo "[info] filter root: $FILTER_ROOT"
echo "[info] mode: $mode"

check_cmd python3
check_cmd cupstestppd
check_cmd cupsfilter

if [[ "$mode" == "coverage" ]]; then
  filters=("${coverage_filters[@]}")
else
  filters=("${minimal_filters[@]}")
fi

for filter in "${filters[@]}"; do
  check_filter "$filter"
done

if [[ "$missing" == "0" ]]; then
  echo "[ok] CUPS filter target check passed"
  echo "export SMT_FUZZER_FILTER_ROOT=$(printf '%q' "$FILTER_ROOT")"
else
  echo "[note] missing tools or filters above; install cups-filters or point SMT_FUZZER_FILTER_ROOT at a build tree"
fi

exit "$missing"
