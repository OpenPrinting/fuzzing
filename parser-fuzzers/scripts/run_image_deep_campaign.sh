#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-imagetops}"
DURATION_SEC="${2:-1200}"
WORKERS="${3:-6}"
TIMEOUT_SEC="${4:-5}"
IMAGE_PROFILE="${5:-auto}"

EXPANSION_LEVEL="${SMT_FUZZER_IMAGE_EXPANSION_LEVEL:-${SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL:-2}}"
OUTPUT_FEEDBACK="${SMT_FUZZER_OUTPUT_FEEDBACK:-auto}"
STRUCTURE_MUTATOR="${SMT_FUZZER_STRUCTURE_MUTATOR:-1}"
MAX_RUN_GB="${SMT_FUZZER_MAX_RUN_GB:-10}"
SKIP_PROBE_RATE="${SMT_FUZZER_SKIP_PROBE_RATE:-0.01}"
VALID_BIAS="${SMT_FUZZER_IMAGE_VALID_BIAS:-1}"
SHORT_PAYLOAD_EVERY="${SMT_FUZZER_IMAGE_SHORT_PAYLOAD_EVERY:-0}"
SKIP_SHORT_ABORTS="${SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS:-1}"
SUMMARY_MODE="${SMT_FUZZER_SUMMARY_MODE:-concise}"
CAPTURE_STDOUT="${SMT_FUZZER_CAPTURE_STDOUT:-0}"
GENERALIZED_SKIP="${SMT_FUZZER_GENERALIZED_SKIP:-0}"
SKIP_ONLY_STOP_AFTER="${SMT_FUZZER_SKIP_ONLY_STOP_AFTER:-20000}"
STAGNATION_STOP_AFTER_SEC="${SMT_FUZZER_STAGNATION_STOP_AFTER_SEC:-300}"
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

case "$TARGET" in
  imagetops)
    CONFIG="configs/parser_targets_image_imagetops_feedback.yaml"
    WORK_ROOT="work/image-deep-imagetops"
    TARGET_ID="image_to_imagetops_feedback"
    ;;
  imagetoraster)
    CONFIG="configs/parser_targets_image_imagetoraster_feedback.yaml"
    WORK_ROOT="work/image-deep-imagetoraster"
    TARGET_ID="image_to_imagetoraster_feedback"
    ;;
  imagetopdf)
    CONFIG="configs/parser_targets_image_imagetopdf_feedback.yaml"
    WORK_ROOT="work/image-deep-imagetopdf"
    TARGET_ID="image_to_imagetopdf_feedback"
    ;;
  all)
    CONFIG="configs/parser_targets_image_feedback.yaml"
    WORK_ROOT="work/image-deep-all"
    TARGET_ID="image_to_imagetoraster_feedback"
    ;;
  *)
    echo "unknown target: $TARGET" >&2
    echo "usage: $0 [imagetops|imagetoraster|imagetopdf|all] [duration_sec] [workers] [timeout_sec] [image_profile|auto]" >&2
    exit 2
    ;;
esac

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

latest_run_dir() {
  local root_dir="$1"
  if [[ ! -d "$root_dir" ]]; then
    return 1
  fi
  find "$root_dir" -maxdepth 2 -type f \( -name summary.concise.json -o -name timeline.jsonl \) -printf '%T@ %h\n' \
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

latest_source_run_dir() {
  local paths=()
  [[ -d work/image-deep-imagetops ]] && paths+=(work/image-deep-imagetops)
  [[ -d work/image-deep-imagetoraster ]] && paths+=(work/image-deep-imagetoraster)
  [[ -d work/image-deep-imagetopdf ]] && paths+=(work/image-deep-imagetopdf)
  [[ -d work/image-feedback-campaign ]] && paths+=(work/image-feedback-campaign)
  [[ ${#paths[@]} -gt 0 ]] || return 1
  find "${paths[@]}" -maxdepth 2 -type f -name summary.concise.json -printf '%T@ %h\n' \
    | sort -nr \
    | sed -n '1s/^[^ ]* //p'
}

if [[ "$IMAGE_PROFILE" == "auto" ]]; then
  if [[ "$PROFILE_POLICY" == "clean-first" ]]; then
    IMAGE_PROFILE="$(latest_file work/template-feedback "*${TARGET}*-feedback.json" || true)"
    if [[ -z "$IMAGE_PROFILE" ]]; then
      IMAGE_PROFILE="$(latest_file work/template-feedback '*imagetopdf*-feedback.json' || true)"
    fi
    if [[ -z "$IMAGE_PROFILE" ]]; then
      IMAGE_PROFILE="$(latest_file work/template-feedback '*imagetoraster*-feedback.json' || true)"
    fi
  fi
  if [[ -z "$IMAGE_PROFILE" ]]; then
    IMAGE_PROFILE="$(latest_file work/template-feedback '*image*-feedback.json' || true)"
  fi
  if [[ -z "$IMAGE_PROFILE" ]]; then
    RUN_DIR="$(latest_source_run_dir || true)"
    if [[ -n "$RUN_DIR" ]]; then
      mkdir -p work/template-feedback
      IMAGE_PROFILE="work/template-feedback/auto-image-$(basename "$RUN_DIR")-feedback.json"
      PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
        --run-dir "$RUN_DIR" \
        --output "$IMAGE_PROFILE" \
        --max-cases-per-kind 256 >&2
    fi
  fi
fi

if [[ "$OUTPUT_FEEDBACK" == "auto" ]]; then
  OUTPUT_FEEDBACK="$(latest_file work/template-feedback "*${TARGET}*-output-feedback.json" || true)"
  if [[ -z "$OUTPUT_FEEDBACK" ]]; then
    OUTPUT_FEEDBACK="$(latest_file work/template-feedback '*image-deep-*-output-feedback.json' || true)"
  fi
fi

echo "target=$TARGET" >&2
echo "target_id=$TARGET_ID" >&2
echo "config=$CONFIG" >&2
echo "work_root=$WORK_ROOT" >&2
echo "image_profile=${IMAGE_PROFILE:-synthetic}" >&2
echo "output_feedback=${OUTPUT_FEEDBACK:-none}" >&2
echo "structure_mutator=$STRUCTURE_MUTATOR" >&2
echo "image_expansion_level=$EXPANSION_LEVEL" >&2
echo "image_valid_bias=$VALID_BIAS" >&2
echo "image_short_payload_every=$SHORT_PAYLOAD_EVERY" >&2
echo "skip_short_image_aborts=$SKIP_SHORT_ABORTS" >&2
echo "skip_probe_rate=$SKIP_PROBE_RATE" >&2
echo "skip_only_stop_after=$SKIP_ONLY_STOP_AFTER" >&2
echo "stagnation_stop_after_sec=$STAGNATION_STOP_AFTER_SEC" >&2
echo "image_cycle_epochs=$CYCLE_EPOCHS" >&2
echo "llvm_profiles=$ENABLE_LLVM_PROFILES" >&2
echo "hazard_skip_after=$HAZARD_SKIP_AFTER" >&2
echo "semantic_skip_after=$SEMANTIC_SKIP_AFTER" >&2
echo "crash_skip_after=$CRASH_SKIP_AFTER" >&2
echo "auto_skip_state=$AUTO_SKIP_STATE" >&2
echo "load_legacy_skip_state=$LOAD_LEGACY_SKIP_STATE" >&2
echo "profile_policy=$PROFILE_POLICY" >&2
echo "summary_mode=$SUMMARY_MODE" >&2
echo "capture_stdout=$CAPTURE_STDOUT" >&2
echo "generalized_skip=$GENERALIZED_SKIP" >&2

ARGS=(
  --config "$CONFIG"
  --work-root "$WORK_ROOT"
  --workers "$WORKERS"
  --timeout-sec "$TIMEOUT_SEC"
  --max-run-gb "$MAX_RUN_GB"
  --duration-sec "$DURATION_SEC"
  --discovery-mode coverage
  --scheduler novelty
  --runtime-skip
  --crash-skip-after "$CRASH_SKIP_AFTER"
  --auto-skip-root work
  --skip-probe-rate "$SKIP_PROBE_RATE"
  --skip-only-stop-after "$SKIP_ONLY_STOP_AFTER"
  --stagnation-stop-after-sec "$STAGNATION_STOP_AFTER_SEC"
  --summary-mode "$SUMMARY_MODE"
  --prune-uninteresting
)

if [[ "$CAPTURE_STDOUT" != "1" && "$CAPTURE_STDOUT" != "true" ]]; then
  ARGS+=(--discard-stdout)
fi

if [[ "$AUTO_SKIP_STATE" == "1" || "$AUTO_SKIP_STATE" == "true" || "$AUTO_SKIP_STATE" == "semantic" ]]; then
  ARGS+=(--auto-skip-state)
fi

if [[ "$GENERALIZED_SKIP" == "1" || "$GENERALIZED_SKIP" == "true" ]]; then
  ARGS+=(--generalized-skip --family-skip-after "${SMT_FUZZER_FAMILY_SKIP_AFTER:-12}")
fi

mkdir -p work
RUN_MARKER="work/.image-deep-${TARGET}-start-$$.marker"
: > "$RUN_MARKER"

if [[ -n "$IMAGE_PROFILE" && -f "$IMAGE_PROFILE" ]]; then
  SMT_FUZZER_IMAGE_FEEDBACK="$IMAGE_PROFILE" \
  SMT_FUZZER_OUTPUT_FEEDBACK="${OUTPUT_FEEDBACK:-}" \
  SMT_FUZZER_STRUCTURE_MUTATOR="$STRUCTURE_MUTATOR" \
  SMT_FUZZER_TARGET_ID="$TARGET_ID" \
  SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="$EXPANSION_LEVEL" \
  SMT_FUZZER_IMAGE_CYCLE_EPOCHS="$CYCLE_EPOCHS" \
  SMT_FUZZER_IMAGE_VALID_BIAS="$VALID_BIAS" \
  SMT_FUZZER_IMAGE_SHORT_PAYLOAD_EVERY="$SHORT_PAYLOAD_EVERY" \
  SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS="$SKIP_SHORT_ABORTS" \
  SMT_FUZZER_ENABLE_LLVM_PROFILES="$ENABLE_LLVM_PROFILES" \
  SMT_FUZZER_HAZARD_SKIP_AFTER="$HAZARD_SKIP_AFTER" \
  SMT_FUZZER_SEMANTIC_SKIP_AFTER="$SEMANTIC_SKIP_AFTER" \
  SMT_FUZZER_LOAD_LEGACY_SKIP_STATE="$LOAD_LEGACY_SKIP_STATE" \
  PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
else
  SMT_FUZZER_OUTPUT_FEEDBACK="${OUTPUT_FEEDBACK:-}" \
  SMT_FUZZER_STRUCTURE_MUTATOR="$STRUCTURE_MUTATOR" \
  SMT_FUZZER_TARGET_ID="$TARGET_ID" \
  SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL="$EXPANSION_LEVEL" \
  SMT_FUZZER_IMAGE_CYCLE_EPOCHS="$CYCLE_EPOCHS" \
  SMT_FUZZER_IMAGE_VALID_BIAS="$VALID_BIAS" \
  SMT_FUZZER_IMAGE_SHORT_PAYLOAD_EVERY="$SHORT_PAYLOAD_EVERY" \
  SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS="$SKIP_SHORT_ABORTS" \
  SMT_FUZZER_ENABLE_LLVM_PROFILES="$ENABLE_LLVM_PROFILES" \
  SMT_FUZZER_HAZARD_SKIP_AFTER="$HAZARD_SKIP_AFTER" \
  SMT_FUZZER_SEMANTIC_SKIP_AFTER="$SEMANTIC_SKIP_AFTER" \
  SMT_FUZZER_LOAD_LEGACY_SKIP_STATE="$LOAD_LEGACY_SKIP_STATE" \
  PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "${ARGS[@]}"
fi

RUN_DIR="$(latest_run_dir_since "$WORK_ROOT" "$RUN_MARKER" || true)"
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$(latest_run_dir "$WORK_ROOT")"
fi
if [[ ! -f "$RUN_DIR/summary.concise.json" ]]; then
  PYTHONPATH=src python3 -m parser_fuzzers.cli recover-run-summary --run-dir "$RUN_DIR" >&2
fi
STAMP="$(date +%Y-%m-%d)-image-deep-${TARGET}-$(date +%H%M%S)"
FINDINGS_DIR="findings/$STAMP"
mkdir -p "$FINDINGS_DIR"

PYTHONPATH=src python3 -m parser_fuzzers.cli dedup-crashes \
  --run-dir "$RUN_DIR" \
  --output-json "$FINDINGS_DIR/dedup.json" \
  --output-md "$FINDINGS_DIR/dedup.md"

mkdir -p work/template-feedback
NEXT_PROFILE="work/template-feedback/image-deep-${TARGET}-$(basename "$RUN_DIR")-feedback.json"
PYTHONPATH=src python3 -m parser_fuzzers.cli build-template-feedback \
  --run-dir "$RUN_DIR" \
  --output "$NEXT_PROFILE" \
  --max-cases-per-kind 256
NEXT_OUTPUT_FEEDBACK="work/template-feedback/image-deep-${TARGET}-$(basename "$RUN_DIR")-output-feedback.json"
PYTHONPATH=src python3 -m parser_fuzzers.cli build-output-feedback \
  --run-dir "$RUN_DIR" \
  --output "$NEXT_OUTPUT_FEEDBACK"

cp "$RUN_DIR/summary.concise.json" "$FINDINGS_DIR/summary.concise.json"
cp "$RUN_DIR/summary.json" "$FINDINGS_DIR/summary.json"
cp "$RUN_DIR/run.log" "$FINDINGS_DIR/run.log"
cp "$RUN_DIR/run_manifest.json" "$FINDINGS_DIR/run_manifest.json"
if [[ -f "$RUN_DIR/discovery_state.json" ]]; then
  cp "$RUN_DIR/discovery_state.json" "$FINDINGS_DIR/discovery_state.json"
fi
cp "$CONFIG" "$FINDINGS_DIR/target_config.yaml"
cp "$NEXT_PROFILE" "$FINDINGS_DIR/next-feedback.json"
cp "$NEXT_OUTPUT_FEEDBACK" "$FINDINGS_DIR/next-output-feedback.json"

cat > "$FINDINGS_DIR/README.md" <<EOF
# Image Deep Campaign

target: $TARGET
run_dir: $RUN_DIR
profile: ${IMAGE_PROFILE:-synthetic}
output_feedback: ${OUTPUT_FEEDBACK:-none}
next_profile: $NEXT_PROFILE
next_output_feedback: $NEXT_OUTPUT_FEEDBACK
duration_sec: $DURATION_SEC
workers: $WORKERS
timeout_sec: $TIMEOUT_SEC
summary_mode: $SUMMARY_MODE
capture_stdout: $CAPTURE_STDOUT
skip_probe_rate: $SKIP_PROBE_RATE
skip_only_stop_after: $SKIP_ONLY_STOP_AFTER
stagnation_stop_after_sec: $STAGNATION_STOP_AFTER_SEC
image_cycle_epochs: $CYCLE_EPOCHS
llvm_profiles: $ENABLE_LLVM_PROFILES
hazard_skip_after: $HAZARD_SKIP_AFTER
semantic_skip_after: $SEMANTIC_SKIP_AFTER
crash_skip_after: $CRASH_SKIP_AFTER
auto_skip_state: $AUTO_SKIP_STATE
load_legacy_skip_state: $LOAD_LEGACY_SKIP_STATE
profile_policy: $PROFILE_POLICY
valid_bias: $VALID_BIAS
structure_mutator: $STRUCTURE_MUTATOR
skip_short_image_aborts: $SKIP_SHORT_ABORTS
generalized_skip: $GENERALIZED_SKIP
EOF

tar -czf "$FINDINGS_DIR.tar.gz" -C findings "$STAMP"

echo "run_dir=$RUN_DIR"
echo "findings_dir=$FINDINGS_DIR"
echo "archive=$FINDINGS_DIR.tar.gz"
echo "next_profile=$NEXT_PROFILE"
echo "next_output_feedback=$NEXT_OUTPUT_FEEDBACK"
