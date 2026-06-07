#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${1:-1200}"
WORKERS="${2:-10}"
TIMEOUT_SEC="${3:-5}"
FEEDBACK_PROFILE="${4:-auto}"
SEED_SKIP_STATE="${5:-}"
FAMILY_SKIP_AFTER="${6:-12}"
MAX_RUN_GB="${SMT_FUZZER_MAX_RUN_GB:-10}"
SKIP_PROBE_RATE="${SMT_FUZZER_SKIP_PROBE_RATE:-0.01}"

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
  [[ -d work/feedback-campaign ]] && paths+=(work/feedback-campaign)
  [[ -d work/structural-campaign ]] && paths+=(work/structural-campaign)
  [[ -d work/deep-coverage ]] && paths+=(work/deep-coverage)
  [[ -d work/general-parser ]] && paths+=(work/general-parser)
  [[ ${#paths[@]} -gt 0 ]] || return 1
  find "${paths[@]}" -maxdepth 2 -type f -name summary.concise.json -printf '%T@ %h\n' \
    | sort -nr \
    | sed -n '1s/^[^ ]* //p'
}

if [[ "$FEEDBACK_PROFILE" == "auto" ]]; then
  FEEDBACK_PROFILE="$(latest_file work/template-feedback '*-feedback.json' || true)"
  if [[ -z "$FEEDBACK_PROFILE" ]]; then
    RUN_DIR="$(latest_campaign_dir || true)"
    if [[ -z "$RUN_DIR" ]]; then
      echo "No feedback profile or previous campaign found. Run a structural/feedback campaign first." >&2
      exit 2
    fi
    mkdir -p work/template-feedback
    FEEDBACK_PROFILE="work/template-feedback/auto-$(basename "$RUN_DIR")-feedback.json"
    PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
      --run-dir "$RUN_DIR" \
      --output "$FEEDBACK_PROFILE" \
      --max-cases-per-kind 160 >&2
  fi
fi

echo "feedback_profile=$FEEDBACK_PROFILE" >&2
echo "max_run_gb=$MAX_RUN_GB" >&2
echo "skip_probe_rate=$SKIP_PROBE_RATE" >&2

ARGS=(
  --config configs/parser_targets_feedback.yaml
  --work-root work/feedback-campaign
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --max-run-gb "$MAX_RUN_GB"
  --duration-sec "$DURATION_SEC"
  --discard-stdout
  --discovery-mode coverage
  --scheduler novelty
  --runtime-skip
  --generalized-skip
  --family-skip-after "$FAMILY_SKIP_AFTER"
  --skip-probe-rate "$SKIP_PROBE_RATE"
  --prune-uninteresting
)

if [[ -n "$SEED_SKIP_STATE" ]]; then
  ARGS+=(--seed-skip-state "$SEED_SKIP_STATE")
else
  ARGS+=(--auto-skip-state --auto-skip-root work)
fi

SMT_FUZZER_TEMPLATE_FEEDBACK="$FEEDBACK_PROFILE" \
  PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
