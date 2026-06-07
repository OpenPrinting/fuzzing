#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

target="${1:-pwgtopdf}"
afl_seconds="${2:-1200}"
template_seconds="${3:-1200}"
monitor_interval="${4:-300}"
workers="${SMT_TEMPLATE_REAL_WORKERS:-4}"
timeout_sec="${SMT_TEMPLATE_REAL_TIMEOUT_SEC:-5}"
max_run_gb="${SMT_TEMPLATE_REAL_MAX_RUN_GB:-10}"
base_config="${SMT_TEMPLATE_REAL_CONFIG:-configs/parser_targets_afl_pwg_feedback.yaml}"
work_root="${SMT_TEMPLATE_REAL_WORK_ROOT:-work/template-real-afl}"
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
    echo "usage: $0 [pwgtopdf|pwgtopclm] [afl-seconds] [template-seconds] [monitor-interval]" >&2
    exit 2
    ;;
esac

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
echo "mode=template-to-real-afl"
echo "target=$target"
echo "template_target_id=$template_target_id"
echo "filter_binary=$filter_binary"
echo "template_seconds=$template_seconds"
echo "afl_seconds=$afl_seconds"
echo "monitor_interval=$monitor_interval"

PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor \
  --config "$filtered_config" \
  --work-root "$template_root" \
  --workers "$workers" \
  --timeout-sec "$timeout_sec" \
  --duration-sec "$template_seconds" \
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
scripts/run_afl_pwg_frontier.sh "$target" "$afl_seconds" "$monitor_interval" >"$campaign_dir/afl-run.stdout" 2>"$campaign_dir/afl-run.stderr"

python3 - "$campaign_dir" "$template_run" "$seed_dir" "$afl_campaign_dir" "$template_seconds" "$afl_seconds" <<'PY'
from pathlib import Path
import json
import sys

campaign_dir, template_run, seed_dir, afl_campaign_dir, template_seconds, afl_seconds = sys.argv[1:]
manifest = {
    "campaign_dir": campaign_dir,
    "mode": "template-to-real-afl",
    "template_run": template_run,
    "seed_dir": seed_dir,
    "afl_campaign_dir": afl_campaign_dir,
    "template_seconds": int(template_seconds),
    "afl_seconds": int(afl_seconds),
}
Path(campaign_dir, "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "campaign_dir=$campaign_dir"
echo "template_run=$template_run"
echo "template_metrics=$template_run/standard_metrics.json"
echo "seed_dir=$seed_dir"
echo "seed_export=$campaign_dir/seed-export.json"
echo "afl_campaign_dir=$afl_campaign_dir"
echo "afl_metrics=$afl_campaign_dir/standard-metrics.json"
