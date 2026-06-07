#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

duration_sec="${1:-1200}"
target_id="${2:-pwg_to_pdf_afl_feedback}"
extension="${3:-.pwg}"
binary="${SMT_FUZZER_AFL_BINARY:-work/afl/bin/template_probe}"
config="${SMT_TEMPLATE_AFL_CONFIG:-configs/parser_targets_afl_pwg_feedback.yaml}"
work_root="${SMT_TEMPLATE_AFL_WORK_ROOT:-work/template-afl-loop}"
timeout_sec="${SMT_TEMPLATE_AFL_TIMEOUT_SEC:-5}"
workers="${SMT_TEMPLATE_AFL_WORKERS:-4}"
max_run_gb="${SMT_TEMPLATE_AFL_MAX_RUN_GB:-10}"
afl_target="${SMT_TEMPLATE_AFL_AFL_TARGET:-template_probe_pwg}"
afl_config="${SMT_TEMPLATE_AFL_AFL_CONFIG:-A1}"
filter_root="${SMT_TEMPLATE_FILTER_ROOT:-${SMT_FUZZER_TEMPLATE_FILTER_ROOT:-${SMT_FUZZER_FILTER_ROOT:-/data/pre-gsoc/cups-filters}}}"

prompt_filter_root() {
  local answer
  if [[ "${SMT_TEMPLATE_SKIP_FILTER_PROMPT:-0}" == "1" ]]; then
    return
  fi
  if [[ -t 0 ]]; then
    printf 'Template runner filter root [%s]: ' "$filter_root"
    read -r answer
    if [[ -n "$answer" ]]; then
      filter_root="$answer"
    fi
  fi
}

check_filter_root() {
  if [[ ! -d "$filter_root" ]]; then
    echo "missing template filter root: $filter_root" >&2
    echo "set SMT_TEMPLATE_FILTER_ROOT or enter a directory containing cups-filters binaries" >&2
    exit 2
  fi
}

if [[ ! -x "$binary" ]]; then
  scripts/build_afl_template_probe.sh "$binary" >/dev/null
fi

prompt_filter_root
check_filter_root

stamp="$(date +%Y%m%d-%H%M%S)"
campaign_dir="$work_root/$stamp"
mkdir -p "$campaign_dir"

template_sec=$((duration_sec / 4))
afl_sec=$((duration_sec / 2))
feedback_sec=$((duration_sec - template_sec - afl_sec))
if (( template_sec < 60 )); then template_sec=60; fi
if (( afl_sec < 60 )); then afl_sec=60; fi
if (( feedback_sec < 60 )); then feedback_sec=60; fi

echo "campaign_dir=$campaign_dir"
echo "duration_sec=$duration_sec"
echo "template_sec=$template_sec"
echo "afl_sec=$afl_sec"
echo "feedback_sec=$feedback_sec"
echo "target_id=$target_id"
echo "extension=$extension"
echo "binary=$binary"
echo "filter_root=$filter_root"

template_root="$campaign_dir/template"
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$config" \
  --work-root "$template_root" \
  --filter-root "$filter_root" \
  --workers "$workers" \
  --timeout-sec "$timeout_sec" \
  --duration-sec "$template_sec" \
  --max-run-gb "$max_run_gb" \
  --discard-stdout \
  --discovery-mode coverage \
  --scheduler novelty \
  --runtime-skip \
  --summary-mode concise \
  --prune-uninteresting >"$campaign_dir/template.stdout.json"

template_run="$(find "$template_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | sed -n '1s/^[^ ]* //p')"
if [[ -z "$template_run" ]]; then
  echo "template run not found" >&2
  exit 1
fi

seed_dir="$campaign_dir/seeds"
PYTHONPATH=src python3 -m parser_fuzzers.cli export-template-seeds \
  --run-dir "$template_run" \
  --target-id "$target_id" \
  --extension "$extension" \
  --output-dir "$seed_dir" \
  --limit 512 >"$campaign_dir/seed-export.json"

afl_out="$campaign_dir/afl-out"
PYTHONPATH=src python3 -m parser_fuzzers.cli afl-run \
  --target "$afl_target" \
  --config "$afl_config" \
  --binary "$binary" \
  --input-dir "$seed_dir" \
  --output-dir "$afl_out" \
  --duration-sec "$afl_sec" \
  --timeout-ms 1000 \
  --memory-mb 1024 \
  --execute >"$campaign_dir/afl-run.log" 2>&1

PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir "$campaign_dir" \
  --afl-output-dir "$afl_out" \
  --output "$campaign_dir/afl-standard-metrics.json" >"$campaign_dir/afl-standard-metrics.stdout.json"

import_dir="$campaign_dir/afl-feedback-import"
feedback_profile="$campaign_dir/afl-feedback-profile.json"
PYTHONPATH=src scripts/import_afl_frontier_feedback.py \
  --afl-out "$afl_out" \
  --target-id "$target_id" \
  --output-run-dir "$import_dir" \
  --extension "$extension" \
  --queue-limit 512 \
  --crash-limit 128 \
  --queue-mode new >"$campaign_dir/afl-import.json"

PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
  --run-dir "$import_dir" \
  --output "$feedback_profile" \
  --max-cases-per-kind 256 >"$campaign_dir/feedback-profile-build.json"

feedback_root="$campaign_dir/feedback-template"
SMT_FUZZER_TEMPLATE_FEEDBACK="$feedback_profile" \
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$config" \
  --work-root "$feedback_root" \
  --filter-root "$filter_root" \
  --workers "$workers" \
  --timeout-sec "$timeout_sec" \
  --duration-sec "$feedback_sec" \
  --max-run-gb "$max_run_gb" \
  --discard-stdout \
  --discovery-mode coverage \
  --scheduler novelty \
  --runtime-skip \
  --summary-mode concise \
  --prune-uninteresting >"$campaign_dir/feedback-template.stdout.json"

feedback_run="$(find "$feedback_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | sed -n '1s/^[^ ]* //p')"

cat >"$campaign_dir/loop_manifest.json" <<EOF
{
  "campaign_dir": "$campaign_dir",
  "template_run": "$template_run",
  "seed_dir": "$seed_dir",
  "afl_out": "$afl_out",
  "import_dir": "$import_dir",
  "feedback_profile": "$feedback_profile",
  "feedback_run": "$feedback_run",
  "filter_root": "$filter_root",
  "duration_sec": $duration_sec,
  "template_sec": $template_sec,
  "afl_sec": $afl_sec,
  "feedback_sec": $feedback_sec
}
EOF

PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-loop-metrics \
  --campaign-dir "$campaign_dir" \
  --output "$campaign_dir/loop_standard_metrics.json" >"$campaign_dir/loop-standard-metrics.stdout.json"

echo "campaign_dir=$campaign_dir"
echo "template_run=$template_run"
echo "seed_dir=$seed_dir"
echo "afl_out=$afl_out"
echo "feedback_profile=$feedback_profile"
echo "feedback_run=$feedback_run"
echo "loop_metrics=$campaign_dir/loop_standard_metrics.json"
