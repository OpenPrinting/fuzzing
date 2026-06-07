#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION="${1:-${SMT_FUZZER_COLD_DURATION:-1200}}"
WORKERS="${SMT_FUZZER_COLD_WORKERS:-10}"
TIMEOUT_SEC="${SMT_FUZZER_COLD_TIMEOUT_SEC:-5}"
MAX_RUN_GB="${SMT_FUZZER_MAX_RUN_GB:-6}"
MIN_FREE_GB="${SMT_FUZZER_MIN_FREE_GB:-40}"
WORK_ROOT="${SMT_FUZZER_COLD_WORK_ROOT:-work/cold-semantic-campaign}"
CONFIG="${SMT_FUZZER_COLD_CONFIG:-configs/parser_targets_cold_semantic.yaml}"

free_gb() {
  df -Pk /data | awk 'NR == 2 { printf "%d", $4 / 1024 / 1024 }'
}

latest_file() {
  local pattern="$1"
  find work/template-feedback -maxdepth 1 -type f -name "$pattern" -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | awk 'NR == 1 { print $2 }'
}

preferred_feedback() {
  local preferred="$1"
  local fallback_pattern="$2"
  if [[ -f "$preferred" ]]; then
    echo "$preferred"
    return 0
  fi
  latest_file "$fallback_pattern"
}

before_free="$(free_gb)"
if (( before_free < MIN_FREE_GB )); then
  echo "stop: free space below threshold: ${before_free}G < ${MIN_FREE_GB}G" >&2
  exit 3
fi

mkdir -p "$WORK_ROOT" work/template-feedback

template_feedback="${SMT_FUZZER_TEMPLATE_FEEDBACK:-$(preferred_feedback 'work/template-feedback/cold-semantic-feedback.json' '*-feedback.json')}"
output_feedback="${SMT_FUZZER_OUTPUT_FEEDBACK:-$(preferred_feedback 'work/template-feedback/cold-semantic-output-feedback.json' '*-output-feedback.json')}"

echo "cold_semantic_campaign"
echo "config=$CONFIG"
echo "work_root=$WORK_ROOT"
echo "duration_sec=$DURATION"
echo "workers=$WORKERS"
echo "timeout_sec=$TIMEOUT_SEC"
echo "max_run_gb=$MAX_RUN_GB"
echo "min_free_gb=$MIN_FREE_GB"
echo "free_gb_before=$before_free"
echo "template_feedback=$template_feedback"
echo "output_feedback=$output_feedback"
echo "avoidance_probe_interval=${SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL:-32}"
echo "avoidance_skip_probe_rate=${SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE:-0.06}"
echo "avoidance_scheduler_penalty_cap=${SMT_FUZZER_AVOIDANCE_SCHEDULER_PENALTY_CAP:-2.0}"

SMT_FUZZER_TEMPLATE_FEEDBACK="$template_feedback" \
SMT_FUZZER_OUTPUT_FEEDBACK="$output_feedback" \
SMT_FUZZER_STRUCTURE_MUTATOR=1 \
SMT_FUZZER_AUTO_DIMENSIONS="${SMT_FUZZER_AUTO_DIMENSIONS:-1}" \
SMT_FUZZER_AUTO_DIMENSION_BUDGET="${SMT_FUZZER_AUTO_DIMENSION_BUDGET:-64}" \
SMT_FUZZER_CRASH_AVOIDANCE="${SMT_FUZZER_CRASH_AVOIDANCE:-1}" \
SMT_FUZZER_CRASH_AVOIDANCE_STATE="${SMT_FUZZER_CRASH_AVOIDANCE_STATE:-auto}" \
SMT_FUZZER_CRASH_AVOIDANCE_ROOT="${SMT_FUZZER_CRASH_AVOIDANCE_ROOT:-work}" \
SMT_FUZZER_CRASH_AVOIDANCE_GENERALIZE="${SMT_FUZZER_CRASH_AVOIDANCE_GENERALIZE:-1}" \
SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL="${SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL:-32}" \
SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE="${SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE:-0.06}" \
SMT_FUZZER_AVOIDANCE_SCHEDULER_PENALTY_CAP="${SMT_FUZZER_AVOIDANCE_SCHEDULER_PENALTY_CAP:-2.0}" \
SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="${SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL:-2}" \
SMT_FUZZER_SKIP_WARM_TEMPLATE_CACHE="${SMT_FUZZER_SKIP_WARM_TEMPLATE_CACHE:-1}" \
SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS="${SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS:-8}" \
SMT_FUZZER_HAZARD_SKIP_AFTER="${SMT_FUZZER_HAZARD_SKIP_AFTER:-24}" \
SMT_FUZZER_SEMANTIC_SKIP_AFTER="${SMT_FUZZER_SEMANTIC_SKIP_AFTER:-3}" \
SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS="${SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS:-1}" \
SMT_FUZZER_LOAD_LEGACY_SKIP_STATE="${SMT_FUZZER_LOAD_LEGACY_SKIP_STATE:-1}" \
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$CONFIG" \
  --work-root "$WORK_ROOT" \
  --workers "$WORKERS" \
  --timeout-sec "$TIMEOUT_SEC" \
  --duration-sec "$DURATION" \
  --max-run-gb "$MAX_RUN_GB" \
  --discard-stdout \
  --discovery-mode coverage \
  --scheduler novelty \
  --min-target-share "${SMT_FUZZER_MIN_TARGET_SHARE:-0.03}" \
  --max-target-share "${SMT_FUZZER_MAX_TARGET_SHARE:-0.16}" \
  --runtime-skip \
  --auto-skip-state \
  --auto-skip-root work \
  --generalized-skip \
  --family-skip-after "${SMT_FUZZER_FAMILY_SKIP_AFTER:-24}" \
  --skip-probe-rate "${SMT_FUZZER_SKIP_PROBE_RATE:-0.03}" \
  --summary-mode concise \
  --prune-uninteresting

run_dir="$(find "$WORK_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk 'NR == 1 { print $2 }')"
if [[ -n "$run_dir" ]]; then
  PYTHONPATH=src python3 -m parser_fuzzers.cli dedup-crashes \
    --run-dir "$run_dir" \
    --output-json "$run_dir/dedup.json" \
    --output-md "$run_dir/dedup.md"
  PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
    --run-dir "$run_dir" \
    --output "work/template-feedback/cold-semantic-feedback.json" \
    --max-cases-per-kind "${SMT_FUZZER_COLD_FEEDBACK_CASES:-192}"
  PYTHONPATH=src python3 -m parser_fuzzers.cli build-output-feedback \
    --run-dir "$run_dir" \
    --output "work/template-feedback/cold-semantic-output-feedback.json"
  echo "run_dir=$run_dir"
  echo "dedup=$run_dir/dedup.md"
  echo "template_feedback=work/template-feedback/cold-semantic-feedback.json"
  echo "output_feedback=work/template-feedback/cold-semantic-output-feedback.json"
fi

echo "free_gb_after=$(free_gb)"
