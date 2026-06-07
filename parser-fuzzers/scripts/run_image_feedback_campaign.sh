#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-900}"
WORKERS="${2:-6}"
TIMEOUT_SEC="${3:-5}"
IMAGE_PROFILE="${4:-auto}"
EXPANSION_LEVEL="${SMT_FUZZER_IMAGE_EXPANSION_LEVEL:-${SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL:-1}}"
MAX_RUN_GB="${SMT_FUZZER_MAX_RUN_GB:-10}"
SKIP_PROBE_RATE="${SMT_FUZZER_SKIP_PROBE_RATE:-0.01}"
MIN_TARGET_SHARE="${SMT_FUZZER_MIN_TARGET_SHARE:-0.18}"
MAX_TARGET_SHARE="${SMT_FUZZER_MAX_TARGET_SHARE:-0.60}"

cd "$ROOT"

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

latest_campaign_dir() {
  local paths=()
  [[ -d work/image-feedback-campaign ]] && paths+=(work/image-feedback-campaign)
  [[ -d work/coverage-discovery ]] && paths+=(work/coverage-discovery)
  [[ -d work/deep-coverage ]] && paths+=(work/deep-coverage)
  [[ -d work/general-parser ]] && paths+=(work/general-parser)
  [[ -d work/feedback-campaign ]] && paths+=(work/feedback-campaign)
  [[ ${#paths[@]} -gt 0 ]] || return 1
  find "${paths[@]}" -maxdepth 2 -type f -name summary.concise.json -printf '%T@ %h\n' \
    | sort -nr \
    | sed -n '1s/^[^ ]* //p'
}

if [[ "$IMAGE_PROFILE" == "auto" ]]; then
  IMAGE_PROFILE="$(latest_file work/template-feedback '*image*-feedback.json' || true)"
  if [[ -z "$IMAGE_PROFILE" ]]; then
    RUN_DIR="$(latest_campaign_dir || true)"
    if [[ -n "$RUN_DIR" ]]; then
      mkdir -p work/template-feedback
      IMAGE_PROFILE="work/template-feedback/auto-image-$(basename "$RUN_DIR")-feedback.json"
      PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
        --run-dir "$RUN_DIR" \
        --output "$IMAGE_PROFILE" \
        --max-cases-per-kind 192 >&2
    fi
  fi
fi

echo "image_profile=${IMAGE_PROFILE:-synthetic}" >&2
echo "image_expansion_level=$EXPANSION_LEVEL" >&2
echo "max_run_gb=$MAX_RUN_GB" >&2
echo "skip_probe_rate=$SKIP_PROBE_RATE" >&2
echo "min_target_share=$MIN_TARGET_SHARE" >&2
echo "max_target_share=$MAX_TARGET_SHARE" >&2

ARGS=(
  --config configs/parser_targets_image_feedback.yaml
  --work-root work/image-feedback-campaign
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --max-run-gb "$MAX_RUN_GB"
  --duration-sec "$DURATION_SEC"
  --discard-stdout
  --discovery-mode coverage
  --scheduler novelty
  --min-target-share "$MIN_TARGET_SHARE"
  --max-target-share "$MAX_TARGET_SHARE"
  --runtime-skip
  --auto-skip-state
  --auto-skip-root work
  --generalized-skip
  --family-skip-after 12
  --skip-probe-rate "$SKIP_PROBE_RATE"
  --prune-uninteresting
)

if [[ -n "$IMAGE_PROFILE" && -f "$IMAGE_PROFILE" ]]; then
  SMT_FUZZER_IMAGE_FEEDBACK="$IMAGE_PROFILE" \
  SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="$EXPANSION_LEVEL" \
  PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
else
  SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="$EXPANSION_LEVEL" \
  PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
fi
