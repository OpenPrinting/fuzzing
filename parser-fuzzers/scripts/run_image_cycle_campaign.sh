#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOTAL_SEC="${1:-1200}"
WORKERS="${2:-8}"
TIMEOUT_SEC="${3:-5}"
TARGETS_CSV="${4:-imagetops,imagetoraster,imagetopdf}"
IMAGE_PROFILE="${5:-auto}"

SLICE_SEC="${SMT_FUZZER_IMAGE_CYCLE_SLICE_SEC:-420}"
MIN_SLICE_SEC="${SMT_FUZZER_IMAGE_CYCLE_MIN_SLICE_SEC:-60}"
STAGNATION_STOP_AFTER_SEC="${SMT_FUZZER_STAGNATION_STOP_AFTER_SEC:-180}"
MIN_FREE_GB="${SMT_FUZZER_MIN_FREE_GB:-20}"
CAMPAIGN_MAX_GB="${SMT_FUZZER_CAMPAIGN_MAX_GB:-30}"
SKIP_PROBE_RATE="${SMT_FUZZER_SKIP_PROBE_RATE:-0.01}"
CYCLE_EPOCHS="${SMT_FUZZER_IMAGE_CYCLE_EPOCHS:-${SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS:-8}}"
ENABLE_LLVM_PROFILES="${SMT_FUZZER_ENABLE_LLVM_PROFILES:-0}"
HAZARD_SKIP_AFTER="${SMT_FUZZER_HAZARD_SKIP_AFTER:-24}"
PROFILE_POLICY="${SMT_FUZZER_IMAGE_PROFILE_POLICY:-clean-first}"
SEMANTIC_SKIP_AFTER="${SMT_FUZZER_SEMANTIC_SKIP_AFTER:-0}"
CRASH_SKIP_AFTER="${SMT_FUZZER_CRASH_SKIP_AFTER:-1}"
AUTO_SKIP_STATE="${SMT_FUZZER_AUTO_SKIP_STATE:-1}"
LOAD_LEGACY_SKIP_STATE="${SMT_FUZZER_LOAD_LEGACY_SKIP_STATE:-1}"
if [[ "$AUTO_SKIP_STATE" == "semantic" ]]; then
  LOAD_LEGACY_SKIP_STATE="0"
fi

cd "$ROOT"

IFS=',' read -r -a TARGETS <<< "$TARGETS_CSV"
if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "no targets configured" >&2
  exit 2
fi

STAMP="$(date +%Y-%m-%d)-image-cycle-$(date +%H%M%S)"
CAMPAIGN_DIR="findings/$STAMP"
mkdir -p "$CAMPAIGN_DIR"

START_EPOCH="$(date +%s)"
END_EPOCH="$((START_EPOCH + TOTAL_SEC))"
ROUND=0
PROFILE="$IMAGE_PROFILE"
OUTPUT_PROFILE="${SMT_FUZZER_OUTPUT_FEEDBACK:-auto}"
STOP_REASON="budget-complete"
CAMPAIGN_RUN_DIRS=()
FINALIZED=0

gb_to_kb() {
  local gb="$1"
  awk -v value="$gb" 'BEGIN { printf "%.0f", value * 1024 * 1024 }'
}

gb_to_bytes() {
  local gb="$1"
  awk -v value="$gb" 'BEGIN { printf "%.0f", value * 1024 * 1024 * 1024 }'
}

available_kb() {
  df -Pk "$ROOT" | awk 'NR == 2 { print $4 }'
}

campaign_bytes() {
  local total=0
  local size=0
  local path=""
  for path in "$CAMPAIGN_DIR" "${CAMPAIGN_RUN_DIRS[@]}"; do
    if [[ -e "$path" ]]; then
      size="$(du -sb "$path" 2>/dev/null | awk '{ print $1 }')"
      total="$((total + ${size:-0}))"
    fi
  done
  echo "$total"
}

guard_disk() {
  local min_free_kb
  min_free_kb="$(gb_to_kb "$MIN_FREE_GB")"
  if [[ "$min_free_kb" -gt 0 && "$(available_kb)" -lt "$min_free_kb" ]]; then
    STOP_REASON="disk-free-low"
    echo "stopping: free disk below ${MIN_FREE_GB}G" >&2
    return 1
  fi

  local max_bytes
  max_bytes="$(gb_to_bytes "$CAMPAIGN_MAX_GB")"
  if [[ "$max_bytes" -gt 0 && "$(campaign_bytes)" -ge "$max_bytes" ]]; then
    STOP_REASON="campaign-size-limit"
    echo "stopping: campaign size reached ${CAMPAIGN_MAX_GB}G" >&2
    return 1
  fi
  return 0
}

finalize_campaign() {
  if [[ "$FINALIZED" -eq 1 ]]; then
    return
  fi
  FINALIZED=1
  FINISHED_EPOCH="$(date +%s)"
  {
    echo
    echo "finished_sec: $((FINISHED_EPOCH - START_EPOCH))"
    echo "stop_reason: $STOP_REASON"
    echo "final_profile: ${PROFILE:-auto}"
    echo "final_output_feedback: ${OUTPUT_PROFILE:-auto}"
  } >> "$CAMPAIGN_DIR/README.md"
  tar -czf "$CAMPAIGN_DIR.tar.gz" -C findings "$STAMP"
  echo "campaign_dir=$CAMPAIGN_DIR"
  echo "archive=$CAMPAIGN_DIR.tar.gz"
  echo "rounds=$ROUND"
  echo "stop_reason=$STOP_REASON"
  echo "final_profile=${PROFILE:-auto}"
  echo "final_output_feedback=${OUTPUT_PROFILE:-auto}"
}

trap 'STOP_REASON="interrupted"; exit 130' INT TERM
trap finalize_campaign EXIT

cat > "$CAMPAIGN_DIR/README.md" <<EOF
# Image Cycle Campaign

total_sec: $TOTAL_SEC
workers: $WORKERS
timeout_sec: $TIMEOUT_SEC
targets: $TARGETS_CSV
initial_profile: $IMAGE_PROFILE
initial_output_feedback: ${OUTPUT_PROFILE:-auto}
slice_sec: $SLICE_SEC
min_slice_sec: $MIN_SLICE_SEC
stagnation_stop_after_sec: $STAGNATION_STOP_AFTER_SEC
skip_probe_rate: $SKIP_PROBE_RATE
image_cycle_epochs: $CYCLE_EPOCHS
llvm_profiles: $ENABLE_LLVM_PROFILES
hazard_skip_after: $HAZARD_SKIP_AFTER
semantic_skip_after: $SEMANTIC_SKIP_AFTER
crash_skip_after: $CRASH_SKIP_AFTER
auto_skip_state: $AUTO_SKIP_STATE
load_legacy_skip_state: $LOAD_LEGACY_SKIP_STATE
profile_policy: $PROFILE_POLICY
min_free_gb: $MIN_FREE_GB
campaign_max_gb: $CAMPAIGN_MAX_GB

Rounds:
EOF

echo "campaign_dir=$CAMPAIGN_DIR" >&2
echo "total_sec=$TOTAL_SEC" >&2
echo "targets=$TARGETS_CSV" >&2
echo "slice_sec=$SLICE_SEC" >&2
echo "stagnation_stop_after_sec=$STAGNATION_STOP_AFTER_SEC" >&2
echo "skip_probe_rate=$SKIP_PROBE_RATE" >&2
echo "image_cycle_epochs=$CYCLE_EPOCHS" >&2
echo "llvm_profiles=$ENABLE_LLVM_PROFILES" >&2
echo "hazard_skip_after=$HAZARD_SKIP_AFTER" >&2
echo "semantic_skip_after=$SEMANTIC_SKIP_AFTER" >&2
echo "crash_skip_after=$CRASH_SKIP_AFTER" >&2
echo "auto_skip_state=$AUTO_SKIP_STATE" >&2
echo "load_legacy_skip_state=$LOAD_LEGACY_SKIP_STATE" >&2
echo "profile_policy=$PROFILE_POLICY" >&2
echo "output_feedback=${OUTPUT_PROFILE:-auto}" >&2
echo "min_free_gb=$MIN_FREE_GB" >&2
echo "campaign_max_gb=$CAMPAIGN_MAX_GB" >&2

while true; do
  if ! guard_disk; then
    break
  fi
  NOW="$(date +%s)"
  REMAINING="$((END_EPOCH - NOW))"
  if [[ "$REMAINING" -lt "$MIN_SLICE_SEC" ]]; then
    STOP_REASON="budget-exhausted"
    break
  fi

  TARGET_INDEX="$((ROUND % ${#TARGETS[@]}))"
  TARGET="${TARGETS[$TARGET_INDEX]}"
  RUN_SEC="$SLICE_SEC"
  if [[ "$RUN_SEC" -gt "$REMAINING" ]]; then
    RUN_SEC="$REMAINING"
  fi

  ROUND_ID="$(printf 'round-%02d-%s' "$((ROUND + 1))" "$TARGET")"
  ROUND_LOG="$CAMPAIGN_DIR/$ROUND_ID.log"
  echo "round=$((ROUND + 1)) target=$TARGET duration_sec=$RUN_SEC profile=${PROFILE:-auto} output_feedback=${OUTPUT_PROFILE:-auto}" >&2

  set +e
  SMT_FUZZER_OUTPUT_FEEDBACK="${OUTPUT_PROFILE:-auto}" \
  SMT_FUZZER_STAGNATION_STOP_AFTER_SEC="$STAGNATION_STOP_AFTER_SEC" \
  SMT_FUZZER_SKIP_PROBE_RATE="$SKIP_PROBE_RATE" \
  SMT_FUZZER_IMAGE_CYCLE_EPOCHS="$CYCLE_EPOCHS" \
  SMT_FUZZER_ENABLE_LLVM_PROFILES="$ENABLE_LLVM_PROFILES" \
  SMT_FUZZER_HAZARD_SKIP_AFTER="$HAZARD_SKIP_AFTER" \
  SMT_FUZZER_SEMANTIC_SKIP_AFTER="$SEMANTIC_SKIP_AFTER" \
  SMT_FUZZER_CRASH_SKIP_AFTER="$CRASH_SKIP_AFTER" \
  SMT_FUZZER_AUTO_SKIP_STATE="$AUTO_SKIP_STATE" \
  SMT_FUZZER_LOAD_LEGACY_SKIP_STATE="$LOAD_LEGACY_SKIP_STATE" \
  SMT_FUZZER_IMAGE_PROFILE_POLICY="$PROFILE_POLICY" \
  scripts/run_image_deep_campaign.sh "$TARGET" "$RUN_SEC" "$WORKERS" "$TIMEOUT_SEC" "$PROFILE" \
    >"$ROUND_LOG" 2>&1
  STATUS="$?"
  set -e

  RUN_DIR="$(sed -n 's/^run_dir=//p' "$ROUND_LOG" | tail -n 1)"
  ROUND_FINDINGS="$(sed -n 's/^findings_dir=//p' "$ROUND_LOG" | tail -n 1)"
  ARCHIVE="$(sed -n 's/^archive=//p' "$ROUND_LOG" | tail -n 1)"
  NEXT_PROFILE="$(sed -n 's/^next_profile=//p' "$ROUND_LOG" | tail -n 1)"
  NEXT_OUTPUT_FEEDBACK="$(sed -n 's/^next_output_feedback=//p' "$ROUND_LOG" | tail -n 1)"
  if [[ -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
    CAMPAIGN_RUN_DIRS+=("$RUN_DIR")
  fi
  if [[ -n "$NEXT_PROFILE" && -f "$NEXT_PROFILE" ]]; then
    PROFILE="$NEXT_PROFILE"
  fi
  if [[ -n "$NEXT_OUTPUT_FEEDBACK" && -f "$NEXT_OUTPUT_FEEDBACK" ]]; then
    OUTPUT_PROFILE="$NEXT_OUTPUT_FEEDBACK"
  fi

  {
    echo "- $ROUND_ID"
    echo "  status: $STATUS"
    echo "  duration_sec: $RUN_SEC"
    echo "  profile: ${PROFILE:-auto}"
    echo "  output_feedback: ${OUTPUT_PROFILE:-auto}"
    echo "  run_dir: ${RUN_DIR:-unknown}"
    echo "  findings_dir: ${ROUND_FINDINGS:-unknown}"
    echo "  archive: ${ARCHIVE:-unknown}"
    echo "  log: $ROUND_LOG"
  } >> "$CAMPAIGN_DIR/README.md"

  printf '{"round":%d,"target":"%s","status":%d,"duration_sec":%d,"run_dir":"%s","findings_dir":"%s","archive":"%s","next_profile":"%s","next_output_feedback":"%s","log":"%s"}\n' \
    "$((ROUND + 1))" "$TARGET" "$STATUS" "$RUN_SEC" \
    "${RUN_DIR:-}" "${ROUND_FINDINGS:-}" "${ARCHIVE:-}" "${NEXT_PROFILE:-}" "${NEXT_OUTPUT_FEEDBACK:-}" "$ROUND_LOG" \
    >> "$CAMPAIGN_DIR/rounds.jsonl"

  if [[ "$STATUS" -ne 0 ]]; then
    STOP_REASON="round-failed"
    echo "round failed: $ROUND_ID, see $ROUND_LOG" >&2
    break
  fi

  ROUND="$((ROUND + 1))"
done
