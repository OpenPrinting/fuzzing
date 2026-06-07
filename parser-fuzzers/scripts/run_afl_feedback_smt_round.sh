#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

feedback_profile="${1:-auto}"
duration_sec="${2:-300}"
workers="${3:-6}"
timeout_sec="${4:-5}"
config="${SMT_AFL_SMT_CONFIG:-configs/parser_targets_afl_pwg_feedback.yaml}"
work_root="${SMT_AFL_SMT_WORK_ROOT:-work/afl-smt-feedback}"
max_run_gb="${SMT_FUZZER_MAX_RUN_GB:-10}"
skip_probe_rate="${SMT_FUZZER_SKIP_PROBE_RATE:-0.02}"
expansion_level="${SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL:-2}"
summary_mode="${SMT_FUZZER_SUMMARY_MODE:-concise}"
capture_stdout="${SMT_AFL_SMT_CAPTURE_STDOUT:-${SMT_FUZZER_CAPTURE_STDOUT:-0}}"

latest_file() {
  local root_dir="$1"
  local pattern="$2"
  if [[ ! -d "$root_dir" ]]; then
    return 1
  fi
  find "$root_dir" -type f -name "$pattern" -printf '%T@ %p\n' \
    | sort -nr \
    | sed -n '1s/^[^ ]* //p'
}

latest_run_dir_since() {
  local root_dir="$1"
  local marker="$2"
  if [[ ! -d "$root_dir" ]]; then
    return 1
  fi
  find "$root_dir" -mindepth 1 -maxdepth 1 -type d -newer "$marker" -printf '%T@ %p\n' \
    | sort -nr \
    | sed -n '1s/^[^ ]* //p'
}

if [[ "$feedback_profile" == "auto" ]]; then
  feedback_profile="$(latest_file work/afl 'afl-feedback.json' || true)"
fi
if [[ -z "$feedback_profile" || ! -f "$feedback_profile" ]]; then
  echo "AFL feedback profile not found. Pass a profile path or run scripts/run_afl_pwg_frontier.sh first." >&2
  exit 2
fi

echo "feedback_profile=$feedback_profile" >&2
echo "config=$config" >&2
echo "work_root=$work_root" >&2
echo "duration_sec=$duration_sec" >&2
echo "workers=$workers" >&2
echo "timeout_sec=$timeout_sec" >&2
echo "template_expansion_level=$expansion_level" >&2
echo "capture_stdout=$capture_stdout" >&2

mkdir -p "$work_root" work/template-feedback
run_marker="work/.afl-smt-feedback-start-$$.marker"
: > "$run_marker"

SMT_FUZZER_TEMPLATE_FEEDBACK="$feedback_profile" \
SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="$expansion_level" \
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$config" \
  --work-root "$work_root" \
  --workers "$workers" \
  --timeout-sec "$timeout_sec" \
  --duration-sec "$duration_sec" \
  --max-run-gb "$max_run_gb" \
  --discovery-mode coverage \
  --scheduler novelty \
  --runtime-skip \
  --auto-skip-state \
  --auto-skip-root work \
  --skip-probe-rate "$skip_probe_rate" \
  --summary-mode "$summary_mode" \
  --prune-uninteresting \
  $(if [[ "$capture_stdout" != "1" && "$capture_stdout" != "true" ]]; then echo "--discard-stdout"; fi)

run_dir="$(latest_run_dir_since "$work_root" "$run_marker" || true)"
if [[ -z "$run_dir" ]]; then
  echo "could not locate new SMT feedback run directory" >&2
  exit 1
fi

next_profile="work/template-feedback/afl-smt-$(basename "$run_dir")-feedback.json"
PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
  --run-dir "$run_dir" \
  --output "$next_profile" \
  --max-cases-per-kind 256

echo "run_dir=$run_dir"
echo "next_profile=$next_profile"
