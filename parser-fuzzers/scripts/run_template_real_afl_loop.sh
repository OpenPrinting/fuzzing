#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

target="${1:-pwgtopdf}"
duration_sec="${2:-1200}"
monitor_interval="${3:-300}"
workers="${SMT_TEMPLATE_REAL_WORKERS:-4}"
timeout_sec="${SMT_TEMPLATE_REAL_TIMEOUT_SEC:-5}"
max_run_gb="${SMT_TEMPLATE_REAL_MAX_RUN_GB:-10}"
base_config="${SMT_TEMPLATE_REAL_CONFIG:-configs/parser_targets_afl_pwg_feedback.yaml}"
work_root="${SMT_TEMPLATE_REAL_LOOP_WORK_ROOT:-work/template-real-afl-loop}"
seed_limit="${SMT_TEMPLATE_REAL_SEED_LIMIT:-512}"

case "$target" in
  pwgtopdf)
    template_target_id="pwg_to_pdf_afl_feedback"
    extension=".pwg"
    ;;
  pwgtopclm)
    template_target_id="pwg_to_pclm_afl_feedback"
    extension=".pwg"
    ;;
  *)
    echo "usage: $0 [pwgtopdf|pwgtopclm] [duration-seconds] [monitor-interval]" >&2
    exit 2
    ;;
esac

template_sec="${SMT_TEMPLATE_REAL_LOOP_TEMPLATE_SEC:-$((duration_sec / 4))}"
afl_sec="${SMT_TEMPLATE_REAL_LOOP_AFL_SEC:-$((duration_sec / 2))}"
feedback_sec="${SMT_TEMPLATE_REAL_LOOP_FEEDBACK_SEC:-$((duration_sec - template_sec - afl_sec))}"
if (( template_sec < 60 )); then template_sec=60; fi
if (( afl_sec < 60 )); then afl_sec=60; fi
if (( feedback_sec < 60 )); then feedback_sec=60; fi

if [[ ! -f work/afl-install/afl-env.sh ]]; then
  bash scripts/build_afl_cupsfilters_stack.sh
fi
source work/afl-install/afl-env.sh

filter_binary="$SMT_AFL_CUPSFILTERS_BIN/$target"
if [[ ! -x "$filter_binary" ]]; then
  echo "missing AFL++ filter binary: $filter_binary" >&2
  exit 2
fi

stamp="$(date +%Y%m%d-%H%M%S)"
campaign_dir="$work_root/${target}-${stamp}"
template_root="$campaign_dir/template"
seed_dir="$campaign_dir/seeds"
afl_campaign_dir="$campaign_dir/afl-standard"
feedback_root="$campaign_dir/feedback-template"
filtered_config="$campaign_dir/template-target.yaml"
mkdir -p "$campaign_dir"

python3 - "$base_config" "$template_target_id" "$filter_binary" "$filtered_config" <<'PY'
from pathlib import Path
import sys
import yaml

base_config, target_id, filter_binary, output = sys.argv[1:]
data = yaml.safe_load(Path(base_config).read_text(encoding="utf-8"))
targets = [item for item in data.get("targets", []) if item.get("id") == target_id]
if not targets:
    raise SystemExit(f"target {target_id!r} not found in {base_config}")
targets[0]["filter_binary"] = filter_binary
Path(output).write_text(yaml.safe_dump({"targets": targets}, sort_keys=False), encoding="utf-8")
PY

export LD_LIBRARY_PATH="$SMT_AFL_LIBCUPSFILTERS_LIB:$SMT_AFL_LIBPPD_LIB:$SMT_AFL_PDFIO_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86}"
export SMT_FUZZER_LIBPPD_ASAN="$SMT_AFL_LIBPPD_LIB"
export SMT_FUZZER_LIBCUPSFILTERS_ASAN="$SMT_AFL_LIBCUPSFILTERS_LIB"
export SMT_FUZZER_PDFIO_LIB="$SMT_AFL_PDFIO_LIB"

echo "campaign_dir=$campaign_dir"
echo "mode=template-real-afl-loop"
echo "target=$target"
echo "template_target_id=$template_target_id"
echo "filter_binary=$filter_binary"
echo "duration_sec=$duration_sec"
echo "template_sec=$template_sec"
echo "afl_sec=$afl_sec"
echo "feedback_sec=$feedback_sec"
echo "monitor_interval=$monitor_interval"

PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$filtered_config" \
  --work-root "$template_root" \
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

set +e
PYTHONPATH=src python3 -m parser_fuzzers.cli dedup-crashes \
  --run-dir "$template_run" \
  --output-json "$template_run/dedup.json" \
  --output-md "$template_run/dedup.md" >/dev/null 2>"$campaign_dir/template-dedup.stderr"
set -e

PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir "$template_run" \
  --output "$template_run/standard_metrics.json" >"$campaign_dir/template-standard-metrics.stdout.json"

PYTHONPATH=src python3 -m parser_fuzzers.cli export-template-seeds \
  --run-dir "$template_run" \
  --target-id "$template_target_id" \
  --extension "$extension" \
  --output-dir "$seed_dir" \
  --limit "$seed_limit" >"$campaign_dir/seed-export.json"

SMT_AFL_CAMPAIGN_DIR="$afl_campaign_dir" \
SMT_AFL_PWG_SEED_DIR="$seed_dir" \
SMT_AFL_DIRECT_INSTRUMENTED=1 \
SMT_AFL_DIRECT_FILTER_BINARY="$filter_binary" \
SMT_AFL_DIRECT_LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
SMT_AFL_IMPORT_QUEUE_MODE=new \
scripts/run_afl_pwg_frontier.sh "$target" "$afl_sec" "$monitor_interval" >"$campaign_dir/afl-run.stdout" 2>"$campaign_dir/afl-run.stderr"

cp "$afl_campaign_dir/standard-metrics.json" "$campaign_dir/afl-standard-metrics.json"
cp "$afl_campaign_dir/afl-import.json" "$campaign_dir/afl-import.json"
cp "$afl_campaign_dir/afl-feedback-build.json" "$campaign_dir/feedback-profile-build.json"
feedback_profile="$afl_campaign_dir/afl-feedback.json"

SMT_FUZZER_TEMPLATE_FEEDBACK="$feedback_profile" \
PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$filtered_config" \
  --work-root "$feedback_root" \
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
if [[ -z "$feedback_run" ]]; then
  echo "feedback template run not found" >&2
  exit 1
fi

set +e
PYTHONPATH=src python3 -m parser_fuzzers.cli dedup-crashes \
  --run-dir "$feedback_run" \
  --output-json "$feedback_run/dedup.json" \
  --output-md "$feedback_run/dedup.md" >/dev/null 2>"$campaign_dir/feedback-dedup.stderr"
set -e

PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-run-metrics \
  --run-dir "$feedback_run" \
  --output "$feedback_run/standard_metrics.json" >"$campaign_dir/feedback-template-standard-metrics.stdout.json"

python3 - "$campaign_dir" "$template_run" "$seed_dir" "$afl_campaign_dir" "$feedback_profile" "$feedback_run" "$duration_sec" "$template_sec" "$afl_sec" "$feedback_sec" <<'PY'
from pathlib import Path
import json
import sys

(
    campaign_dir,
    template_run,
    seed_dir,
    afl_campaign_dir,
    feedback_profile,
    feedback_run,
    duration_sec,
    template_sec,
    afl_sec,
    feedback_sec,
) = sys.argv[1:]
manifest = {
    "campaign_dir": campaign_dir,
    "mode": "template-real-afl-loop",
    "template_run": template_run,
    "seed_dir": seed_dir,
    "afl_out": str(Path(afl_campaign_dir) / "out"),
    "afl_campaign_dir": afl_campaign_dir,
    "import_dir": str(Path(afl_campaign_dir) / "feedback-import"),
    "feedback_profile": feedback_profile,
    "feedback_run": feedback_run,
    "duration_sec": int(duration_sec),
    "template_sec": int(template_sec),
    "afl_sec": int(afl_sec),
    "feedback_sec": int(feedback_sec),
}
Path(campaign_dir, "loop_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

PYTHONPATH=src python3 -m parser_fuzzers.cli summarize-loop-metrics \
  --campaign-dir "$campaign_dir" \
  --output "$campaign_dir/loop_standard_metrics.json" >"$campaign_dir/loop-standard-metrics.stdout.json"

echo "campaign_dir=$campaign_dir"
echo "template_run=$template_run"
echo "template_metrics=$template_run/standard_metrics.json"
echo "seed_dir=$seed_dir"
echo "seed_export=$campaign_dir/seed-export.json"
echo "afl_campaign_dir=$afl_campaign_dir"
echo "afl_metrics=$campaign_dir/afl-standard-metrics.json"
echo "feedback_profile=$feedback_profile"
echo "feedback_run=$feedback_run"
echo "feedback_metrics=$feedback_run/standard_metrics.json"
echo "loop_metrics=$campaign_dir/loop_standard_metrics.json"
