#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

template_run="${1:-work/template-real-afl/pwgtopdf-20260605-120508/template/20260605-120508}"
seconds="${2:-600}"
monitor_interval="${3:-300}"
target_id="${SMT_AFL_BUNDLE_TARGET_ID:-pwg_to_pdf_afl_feedback}"
seed_limit="${SMT_AFL_BUNDLE_SEED_LIMIT:-512}"
dynamic_profile="${SMT_AFL_BUNDLE_DYNAMIC_PROFILE:-}"
dynamic_token_limit="${SMT_AFL_BUNDLE_DYNAMIC_TOKEN_LIMIT:-512}"
dynamic_seed_limit="${SMT_AFL_BUNDLE_DYNAMIC_SEED_LIMIT:-64}"
use_cmplog="${SMT_AFL_BUNDLE_USE_CMPLOG:-auto}"
max_gb="${SMT_AFL_BUNDLE_MAX_GB:-0}"
timestamp="$(date +%Y%m%d-%H%M%S)"
campaign_dir="${SMT_AFL_BUNDLE_CAMPAIGN_DIR:-work/afl/pwg-bundle-${timestamp}}"
seed_dir="$campaign_dir/seeds"
out_dir="$campaign_dir/out"
harness="${SMT_AFL_BUNDLE_HARNESS:-work/afl/bin/pwg_bundle_harness}"
cmplog_harness="${SMT_AFL_BUNDLE_CMPLOG_HARNESS:-${harness}.cmplog}"
fallback_ppd="$campaign_dir/fallback.ppd"

if [[ ! -x "$harness" ]]; then
  scripts/build_afl_pwg_bundle_harness.sh "$harness" >/dev/null
fi
cmplog_args=()
if [[ "$use_cmplog" != "0" ]]; then
  if [[ ! -x "$cmplog_harness" && "$use_cmplog" != "no-build" ]]; then
    SMT_AFL_BUNDLE_CMPLOG=1 scripts/build_afl_pwg_bundle_harness.sh "$cmplog_harness" >/dev/null
  fi
  if [[ -x "$cmplog_harness" ]]; then
    cmplog_args=(-c "$cmplog_harness")
  fi
fi
source work/afl-install/afl-env.sh

mkdir -p "$campaign_dir"
PYTHONPATH=src python3 -c "from pathlib import Path; from parser_fuzzers.ppd_templates import make_ppd; Path('$fallback_ppd').write_text(make_ppd('pwgtopdf_coverage_options', 0), encoding='utf-8')"

scripts/export_pwg_bundle_seeds.py \
  --run-dir "$template_run" \
  --target-id "$target_id" \
  --output-dir "$seed_dir" \
  --limit "$seed_limit" >"$campaign_dir/bundle-seed-export.json"
if [[ -f "$seed_dir/bundle_seed_manifest.json" ]]; then
  mv "$seed_dir/bundle_seed_manifest.json" "$campaign_dir/bundle_seed_manifest.json"
fi
if [[ -n "$dynamic_profile" ]]; then
  if [[ ! -f "$dynamic_profile" ]]; then
    echo "dynamic profile not found: $dynamic_profile" >&2
    exit 2
  fi
  PYTHONPATH=src scripts/augment_pwg_bundle_seeds_from_dynamic_profile.py \
    --seed-dir "$seed_dir" \
    --profile "$dynamic_profile" \
    --limit "$dynamic_seed_limit" >"$campaign_dir/dynamic-seed-augment.json"
fi

export AFL_NO_UI=1
export AFL_SKIP_CPUFREQ=1
export AFL_CRASH_EXITCODE=86
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=0}"
export LD_LIBRARY_PATH="$SMT_AFL_LIBCUPSFILTERS_LIB:$SMT_AFL_LIBPPD_LIB:$SMT_AFL_PDFIO_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export SMT_AFL_BUNDLE_FALLBACK_PPD="$fallback_ppd"

dict_args=()
dict_path="dictionaries/pwg_bundle.dict"
if [[ -n "$dynamic_profile" ]]; then
  dict_path="$campaign_dir/dynamic-pwg-bundle.dict"
  PYTHONPATH=src scripts/dynamic_profile_to_afl_dict.py \
    --profile "$dynamic_profile" \
    --base-dictionary dictionaries/pwg_bundle.dict \
    --output "$dict_path" \
    --max-tokens "$dynamic_token_limit" >"$campaign_dir/dynamic-dict-export.json"
fi
if [[ -f "$dict_path" ]]; then
  dict_args=(-x "$dict_path")
fi

echo "campaign_dir=$campaign_dir"
echo "mode=pwg-bundle-afl"
echo "template_run=$template_run"
echo "seed_dir=$seed_dir"
echo "harness=$harness"
echo "cmplog=$([[ ${#cmplog_args[@]} -gt 0 ]] && echo "$cmplog_harness" || echo none)"
echo "dictionary=$([[ ${#dict_args[@]} -gt 0 ]] && echo "$dict_path" || echo none)"
echo "dynamic_profile=${dynamic_profile:-none}"
echo "duration_sec=$seconds"
echo "monitor_interval_sec=$monitor_interval"
echo "max_gb=$max_gb"
echo "fallback_ppd=$fallback_ppd"

set +e
timeout --kill-after=10s "$seconds" \
afl-fuzz \
  "${dict_args[@]}" \
  "${cmplog_args[@]}" \
  -t "${AFL_BUNDLE_TIMEOUT_MS:-5000}" \
  -m none \
  -i "$seed_dir" \
  -o "$out_dir" \
  -T "parser-fuzzers-pwg-bundle" \
  -- "$harness" @@ >"$campaign_dir/afl.log" 2>&1 &
afl_pid="$!"
set -e

(
  while true; do
    sleep "$monitor_interval"
    scripts/afl_stats_snapshot.py "$out_dir" --label "[bundle-afl]"
    size_bytes="$(du -sb "$campaign_dir" 2>/dev/null | cut -f1 || echo 0)"
    echo "[bundle-afl:disk] campaign_dir=$campaign_dir bytes=$size_bytes max_gb=$max_gb"
    if [[ "$max_gb" != "0" ]]; then
      max_bytes="$(python3 -c "print(int(float('$max_gb') * 1024 * 1024 * 1024))")"
      if [[ "$size_bytes" =~ ^[0-9]+$ && "$size_bytes" -ge "$max_bytes" ]]; then
        echo "[bundle-afl:disk] stopping afl-fuzz: campaign directory reached max_gb=$max_gb"
        kill "$afl_pid" 2>/dev/null || true
        break
      fi
    fi
  done
) &
monitor_pid="$!"

set +e
wait "$afl_pid"
status="$?"
set -e
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true

scripts/afl_stats_snapshot.py "$out_dir" --label "[bundle-afl:final]"

set +e
PYTHONPATH=src scripts/import_afl_frontier_feedback.py \
  --afl-out "$out_dir" \
  --target-id "$target_id" \
  --output-run-dir "$campaign_dir/feedback-import" \
  --extension .pwg-bundle \
  --queue-limit 512 \
  --crash-limit 128 \
  --queue-mode new >"$campaign_dir/afl-import.json" 2>"$campaign_dir/afl-import.stderr"
import_status="$?"
PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir "$campaign_dir/feedback-import" \
  --afl-output-dir "$out_dir" \
  --output "$campaign_dir/standard-metrics.json" >"$campaign_dir/standard-metrics.stdout.json" 2>"$campaign_dir/standard-metrics.stderr"
metrics_status="$?"
set -e

cat >"$campaign_dir/manifest.json" <<EOF
{
  "campaign_dir": "$campaign_dir",
  "mode": "pwg-bundle-afl",
  "template_run": "$template_run",
  "seed_dir": "$seed_dir",
  "harness": "$harness",
  "cmplog_harness": "$([[ ${#cmplog_args[@]} -gt 0 ]] && echo "$cmplog_harness" || echo "")",
  "dictionary": "$([[ ${#dict_args[@]} -gt 0 ]] && echo "$dict_path" || echo "")",
  "dynamic_profile": "${dynamic_profile:-}",
  "max_gb": $max_gb,
  "duration_sec": $seconds,
  "afl_import_status": $import_status,
  "metrics_status": $metrics_status
}
EOF

echo "campaign_dir=$campaign_dir"
echo "afl_import_status=$import_status"
echo "metrics_status=$metrics_status"
echo "standard_metrics=$campaign_dir/standard-metrics.json"
echo "afl_exit_status=$status"
if [[ "$status" == "124" || "$status" == "137" ]]; then
  echo "[note] outer timeout stopped AFL++ after preserving results"
  exit 0
fi
exit "$status"
