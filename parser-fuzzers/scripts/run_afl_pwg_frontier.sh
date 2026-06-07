#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

target="${1:-pwgtopdf}"
seconds="${2:-1800}"
monitor_interval="${3:-300}"
seed_run_dir="${SMT_AFL_PWG_SEED_RUN_DIR:-${AFL_PWG_SEED_RUN_DIR:-work/underexplored-feedback30-campaign/20260603-124945}}"
external_seed_dir="${SMT_AFL_PWG_SEED_DIR:-${AFL_PWG_SEED_DIR:-}}"
seed_limit="${SMT_AFL_PWG_SEED_LIMIT:-${AFL_PWG_SEED_LIMIT:-128}}"
queue_import_limit="${SMT_AFL_IMPORT_QUEUE_LIMIT:-${AFL_IMPORT_QUEUE_LIMIT:-512}}"
crash_import_limit="${SMT_AFL_IMPORT_CRASH_LIMIT:-${AFL_IMPORT_CRASH_LIMIT:-128}}"
queue_import_mode="${SMT_AFL_IMPORT_QUEUE_MODE:-${AFL_IMPORT_QUEUE_MODE:-new}}"
dict_path="${SMT_AFL_DIRECT_DICT:-${AFL_DIRECT_DICT:-dictionaries/pwg_raster.dict}}"
timestamp="$(date +%Y%m%d-%H%M%S)"

case "$target" in
  pwgtopdf)
    target_id="pwg_to_pdf_feedback_f30"
    filter_binary="/data/pre-gsoc/cups-filters/pwgtopdf"
    ppd_kind="pwgtopdf_coverage_options"
    ;;
  pwgtopclm)
    target_id="pwg_to_pclm_feedback_f30"
    filter_binary="/data/pre-gsoc/cups-filters/pwgtopclm"
    ppd_kind="pwgtopclm_coverage_options"
    ;;
  *)
    echo "usage: $0 [pwgtopdf|pwgtopclm] [seconds] [monitor-interval-seconds]" >&2
    exit 2
    ;;
esac
filter_binary="${SMT_AFL_DIRECT_FILTER_BINARY:-${AFL_DIRECT_FILTER_BINARY:-$filter_binary}}"

campaign_dir="${SMT_AFL_CAMPAIGN_DIR:-work/afl/pwg-frontier-${target}-${timestamp}}"
seed_dir="$campaign_dir/seeds"
ppd_path="$campaign_dir/candidate.ppd"
run_log="$campaign_dir/afl.log"
import_run_dir="$campaign_dir/feedback-import"
feedback_profile="$campaign_dir/afl-feedback.json"
mkdir -p "$campaign_dir"

if [[ -n "$external_seed_dir" ]]; then
  if [[ ! -d "$external_seed_dir" ]]; then
    echo "external seed dir not found: $external_seed_dir" >&2
    exit 2
  fi
  mkdir -p "$seed_dir"
  find "$external_seed_dir" -maxdepth 1 -type f -name '*.pwg' -exec cp -a {} "$seed_dir/" \;
  seed_count="$(find "$seed_dir" -maxdepth 1 -type f | wc -l)"
  if [[ "$seed_count" == "0" ]]; then
    echo "external seed dir has no .pwg seeds: $external_seed_dir" >&2
    exit 2
  fi
  echo "prepared $seed_count AFL++ seeds in $seed_dir from external_seed_dir=$external_seed_dir"
else
  scripts/prepare_afl_frontier_corpus.py \
    --run-dir "$seed_run_dir" \
    --target-id "$target_id" \
    --output-dir "$seed_dir" \
    --extension .pwg \
    --limit "$seed_limit"
fi

PYTHONPATH=src python3 -c "from pathlib import Path; from parser_fuzzers.ppd_templates import make_ppd; Path('$ppd_path').write_text(make_ppd('$ppd_kind', 0), encoding='utf-8')"

lib_path="${SMT_AFL_DIRECT_LD_LIBRARY_PATH:-${AFL_DIRECT_LD_LIBRARY_PATH:-}}"
if [[ -z "$lib_path" ]]; then
  lib_path="$(PYTHONPATH=src python3 -c "from parser_fuzzers.multitarget_runner import _local_filter_library_path; print(_local_filter_library_path())")"
fi

export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export AFL_CRASH_EXITCODE=86
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=0}"
export SMT_AFL_DIRECT_FILTER_BINARY="$filter_binary"
export SMT_AFL_DIRECT_PPD="$ppd_path"
export SMT_AFL_DIRECT_JOB_OPTIONS="${SMT_AFL_DIRECT_JOB_OPTIONS:-${AFL_DIRECT_JOB_OPTIONS:-PageSize=Letter ColorModel=Gray PrintQuality=Normal MediaType=Plain}}"
export SMT_AFL_DIRECT_LD_LIBRARY_PATH="$lib_path"
export PPD="$ppd_path"
export CONTENT_TYPE="${SMT_AFL_DIRECT_CONTENT_TYPE:-${AFL_DIRECT_CONTENT_TYPE:-application/vnd.cups-pwg}}"
export FINAL_CONTENT_TYPE="${SMT_AFL_DIRECT_FINAL_CONTENT_TYPE:-${AFL_DIRECT_FINAL_CONTENT_TYPE:-application/pdf}}"
export PRINTER="${SMT_AFL_DIRECT_PRINTER:-${AFL_DIRECT_PRINTER:-parser-fuzzers}}"
export DEVICE_URI="${SMT_AFL_DIRECT_DEVICE_URI:-${AFL_DIRECT_DEVICE_URI:-file:/dev/null}}"
if [[ -n "$lib_path" ]]; then
  export LD_LIBRARY_PATH="$lib_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
direct_instrumented="${SMT_AFL_DIRECT_INSTRUMENTED:-${AFL_DIRECT_INSTRUMENTED:-0}}"
unset AFL_DIRECT_FILTER_BINARY AFL_DIRECT_PPD AFL_DIRECT_JOB_OPTIONS AFL_DIRECT_LD_LIBRARY_PATH AFL_DIRECT_INSTRUMENTED AFL_PWG_SEED_LIMIT AFL_PWG_SEED_RUN_DIR AFL_PWG_SEED_DIR

mode_args=()
if [[ "$direct_instrumented" != "1" ]]; then
  mode_args=(-n)
fi

target_cmd=(scripts/afl_direct_filter_target.sh @@)
if [[ "$direct_instrumented" == "1" ]]; then
  target_cmd=("$filter_binary" 1 afl afl 1 "$SMT_AFL_DIRECT_JOB_OPTIONS" @@)
fi

dict_args=()
if [[ -f "$dict_path" ]]; then
  dict_args=(-x "$dict_path")
fi

cmplog_args=()
cmplog_binary="${SMT_AFL_DIRECT_CMPLOG_BINARY:-${AFL_DIRECT_CMPLOG_BINARY:-${filter_binary}.cmplog}}"
if [[ "$direct_instrumented" == "1" && "${SMT_AFL_USE_CMPLOG:-${AFL_USE_CMPLOG:-auto}}" != "0" && -x "$cmplog_binary" ]]; then
  cmplog_args=(-c "$cmplog_binary")
fi

echo "campaign_dir=$campaign_dir"
echo "seed_dir=$seed_dir"
echo "external_seed_dir=${external_seed_dir:-none}"
echo "target=$target"
echo "filter_binary=$filter_binary"
echo "mode=$([[ ${#mode_args[@]} -gt 0 ]] && echo dumb || echo instrumented)"
echo "target_cmd=${target_cmd[*]}"
echo "dictionary=${dict_path:-none}"
echo "cmplog=$([[ ${#cmplog_args[@]} -gt 0 ]] && echo "$cmplog_binary" || echo none)"
echo "duration_sec=$seconds"
echo "monitor_interval_sec=$monitor_interval"
echo "queue_import_mode=$queue_import_mode"
echo "log=$run_log"

set +e
timeout --kill-after=10s "$seconds" \
afl-fuzz \
  "${mode_args[@]}" \
  "${dict_args[@]}" \
  "${cmplog_args[@]}" \
  -t "${AFL_DIRECT_TIMEOUT_MS:-5000}" \
  -m none \
  -i "$seed_dir" \
  -o "$campaign_dir/out" \
  -T "parser-fuzzers-${target}" \
  -- "${target_cmd[@]}" >"$run_log" 2>&1 &
afl_pid="$!"
set -e

(
  while true; do
    sleep "$monitor_interval"
    scripts/afl_stats_snapshot.py "$campaign_dir/out" --label "[afl:$target]"
  done
) &
monitor_pid="$!"

set +e
wait "$afl_pid"
status="$?"
set -e
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true

scripts/afl_stats_snapshot.py "$campaign_dir/out" --label "[afl:$target:final]"

set +e
PYTHONPATH=src scripts/import_afl_frontier_feedback.py \
  --afl-out "$campaign_dir/out" \
  --target-id "$target_id" \
  --output-run-dir "$import_run_dir" \
  --extension .pwg \
  --queue-limit "$queue_import_limit" \
  --crash-limit "$crash_import_limit" \
  --queue-mode "$queue_import_mode" >"$campaign_dir/afl-import.json" 2>"$campaign_dir/afl-import.stderr"
import_status="$?"
if [[ "$import_status" == "0" ]]; then
  PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
    --run-dir "$import_run_dir" \
    --output "$feedback_profile" \
    --max-cases-per-kind 256 >"$campaign_dir/afl-feedback-build.json" 2>"$campaign_dir/afl-feedback-build.stderr"
  feedback_status="$?"
else
  feedback_status="$import_status"
fi
set -e

metrics_status=0
set +e
PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir "$import_run_dir" \
  --afl-output-dir "$campaign_dir/out" \
  --output "$campaign_dir/standard-metrics.json" >"$campaign_dir/standard-metrics.stdout.json" 2>"$campaign_dir/standard-metrics.stderr"
metrics_status="$?"
set -e

echo "campaign_dir=$campaign_dir"
echo "import_run_dir=$import_run_dir"
echo "feedback_profile=$feedback_profile"
echo "afl_import_status=$import_status"
echo "afl_feedback_status=$feedback_status"
echo "metrics_status=$metrics_status"
echo "standard_metrics=$campaign_dir/standard-metrics.json"
echo "afl_exit_status=$status"
if [[ "$status" == "124" || "$status" == "137" ]]; then
  echo "[note] outer timeout stopped AFL++ after preserving results"
  exit 0
fi
exit "$status"
