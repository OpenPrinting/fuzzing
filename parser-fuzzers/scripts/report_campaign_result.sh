#!/usr/bin/env bash
set -euo pipefail

RUN_DIR="${1:-}"
ASAN_ROOT="${2:-}"

if [[ -z "$RUN_DIR" ]]; then
  echo "usage: $0 <run-dir> [asan-root]" >&2
  exit 2
fi

python3 - "$RUN_DIR" "$ASAN_ROOT" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
asan_root = sys.argv[2] or "work/openprinting-asan"
summary_path = run_dir / "summary.concise.json"
dedup_path = run_dir / "crash_dedup.json"
COLOR_ENABLED = (
    os.environ.get("NO_COLOR") is None
    and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") in {"1", "true", "yes"})
)

COLORS = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
}


def load_json(path):
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def color(name, text):
    if not COLOR_ENABLED:
        return text
    return f"{COLORS[name]}{text}{COLORS['reset']}"


def label(name, text=None):
    text = text or name
    palette = {
        "ok": "green",
        "crash": "red",
        "asan": "red",
        "warn": "yellow",
        "triage": "yellow",
        "files": "cyan",
        "next": "cyan",
    }
    return color(palette.get(name, "bold"), f"[{text}]")


def metric(name, value, bad=False, warn=False):
    rendered = f"{name}={value}"
    if bad:
        return color("red", rendered)
    if warn:
        return color("yellow", rendered)
    return rendered


def infer_filter(command):
    match = re.search(r"/(?:usr/)?(?:lib|libexec)/cups/filter/([A-Za-z0-9_.+-]+)", command)
    if match:
        return match.group(1)
    parts = command.split()
    for part in parts:
        name = Path(part).name
        if name in {
            "rastertopclx",
            "rastertoescpx",
            "rastertops",
            "pwgtoraster",
            "pwgtopdf",
            "pdftopdf",
            "pdftops",
            "pdftoraster",
            "mupdftopwg",
            "imagetoraster",
            "imagetopdf",
            "imagetops",
            "texttopdf",
            "texttotext",
            "gstoraster",
            "gstopdf",
            "gstopxl",
            "pwgtopclm",
            "commandtoescpx",
            "commandtopclx",
        }:
            return name
    return "<filter-name>"


def read_stderr_for_cluster(cluster, rep):
    stderr_path = cluster.get("representative_stderr", "")
    candidates = []
    if stderr_path:
        candidates.append(Path(stderr_path))
    if rep:
        candidates.append(Path(rep) / "stderr.txt")

    for path in candidates:
        if path.exists():
            return path, path.read_text(encoding="utf-8", errors="replace")
    return None, ""


def sanitizer_excerpt(stderr_text, limit_frames=6):
    if not stderr_text:
        return []

    lines = stderr_text.splitlines()
    interesting = []
    seen = set()
    keywords = (
        "ERROR: AddressSanitizer",
        "SUMMARY: AddressSanitizer",
        "AddressSanitizer:",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
        "Sanitizer CHECK failed",
    )

    for line in lines:
        if any(keyword in line for keyword in keywords):
            normalized = " ".join(line.strip().split())
            if normalized and normalized not in seen:
                interesting.append(normalized)
                seen.add(normalized)

    frames = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"#\d+\s+", stripped):
            frames.append(stripped)
            if len(frames) >= limit_frames:
                break

    excerpt = interesting[:4] + frames
    return [line[:240] for line in excerpt]


summary = load_json(summary_path)
dedup = load_json(dedup_path)
crashes = int(dedup.get("crash_records", summary.get("crashes", 0) or 0))
unique = int(dedup.get("unique_crashes", summary.get("unique_crashes", 0) or 0))

print()
print(color("bold", "[campaign-result]"))
print(f"run_dir: {run_dir}")
if summary:
    print(
        "counts: "
        f"{metric('cases', summary.get('cases', 0))} "
        f"{metric('reached', summary.get('reached', 0))} "
        f"{metric('valid_ppds', summary.get('valid_ppds', 0))} "
        f"{metric('crashes', summary.get('crashes', 0), bad=int(summary.get('crashes', 0) or 0) > 0)} "
        f"{metric('timeouts', summary.get('timeouts', 0), warn=int(summary.get('timeouts', 0) or 0) > 0)} "
        f"{metric('unique_runtime', summary.get('unique_crashes', 0), bad=int(summary.get('unique_crashes', 0) or 0) > 0)}"
    )

if crashes == 0:
    print(f"{label('ok')} no crash-classified cases in this run")
    print(f"{label('next')} try a longer ASan run after build: scripts/run_asan_cups_filters_campaign.sh {asan_root} 300 4 5")
    raise SystemExit(0)

print(f"{label('crash')} crash-classified cases={crashes}, unique dedup signatures={unique}")
print(f"{label('files')} dedup report: {run_dir / 'crash_dedup.md'}")

clusters = dedup.get("clusters") or []
for index, cluster in enumerate(clusters[:3], start=1):
    rep = cluster.get("representative_work_dir", "")
    cmd = cluster.get("representative_command", "")
    filter_name = infer_filter(cmd)
    stderr_path, stderr_text = read_stderr_for_cluster(cluster, rep)
    asan_lines = sanitizer_excerpt(stderr_text)
    print()
    print(color("bold", f"[cluster {index}]") + f" target={cluster.get('target_id', '<unknown>')} count={cluster.get('count', 0)}")
    print(f"signature: {color('red', cluster.get('signature', '<unknown>'))}")
    print(f"case: {rep}")
    print(f"command: {cmd}")
    if asan_lines:
        print(f"{label('asan')} sanitizer excerpt from {stderr_path}:")
        for line in asan_lines:
            print(f"  {color('red', line)}")
    else:
        print(f"{label('warn', 'asan')} no sanitizer report in representative stderr")
    if rep:
        print(f"ASan replay: scripts/replay_asan_filter.sh {filter_name} {rep}")
        print(f"GDB triage:  scripts/gdb_crash_filter.sh {filter_name} {rep}")

print()
print(label("triage"))
print("System-filter crashes are reachability signals, not final issue reports.")
print(f"For issue-quality output, build isolated ASan first: scripts/print_cups_filters_build_plan.sh {asan_root}")
PY
