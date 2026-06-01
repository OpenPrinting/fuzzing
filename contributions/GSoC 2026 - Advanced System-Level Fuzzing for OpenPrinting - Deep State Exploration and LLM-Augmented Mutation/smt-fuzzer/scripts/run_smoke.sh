#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT/src"

WORK_DIR="work/smoke"
INPUT="$WORK_DIR/input.bin"
EVENT="$WORK_DIR/event.json"
RESULT="$WORK_DIR/result.json"
OUT_DIR="$WORK_DIR/corpus"

mkdir -p "$WORK_DIR" "$OUT_DIR"

python3 - "$INPUT" "$EVENT" <<'PY'
import json
import sys
from pathlib import Path

from smt_fuzzer.hashing import sha256_file

input_path = Path(sys.argv[1])
event_path = Path(sys.argv[2])
input_path.write_bytes(b"\x00SMT-FUZZER-SMOKE\n")
event = {
    "target_id": "synthetic_eq_u8",
    "input_path": str(input_path),
    "input_sha256": sha256_file(input_path),
    "offset": 0,
    "width": 1,
    "endianness": "little",
    "signed": False,
    "op": "eq",
    "rhs": 65,
    "description": "first byte must become ASCII A",
}
event_path.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

solve_args=()
if [[ "${SMT_FUZZER_STRICT_Z3:-0}" == "1" ]]; then
  echo "[smoke] strict Z3 mode enabled"
else
  solve_args+=(--allow-fallback)
fi

python3 -m smt_fuzzer.cli solve-event --event "$EVENT" --output "$RESULT" "${solve_args[@]}"
patched_path="$(python3 -m smt_fuzzer.cli patch-input --result "$RESULT" --output-dir "$OUT_DIR")"

python3 - "$EVENT" "$patched_path" "$RESULT" <<'PY'
import json
import sys
from pathlib import Path

from smt_fuzzer.models import BranchEvent
from smt_fuzzer.solver import condition_holds, read_event_value

event = BranchEvent.from_dict(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
patched = Path(sys.argv[2]).read_bytes()
result = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
ok = condition_holds(event, read_event_value(event, patched))
print(json.dumps({
    "ok": ok,
    "event": sys.argv[1],
    "result": sys.argv[3],
    "patched_input": sys.argv[2],
    "reason": result["reason"],
}, indent=2, sort_keys=True))
raise SystemExit(0 if ok else 1)
PY

python3 -m smt_fuzzer.cli validate --configs configs
