from __future__ import annotations

import json
import shlex
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from parser_fuzzers.template_feedback import build_feedback_profile, write_feedback_profile


@dataclass(frozen=True)
class AutoExpandPlan:
    search_root: str
    run_dirs: list[str]
    output_profile: str
    expansion_level: int
    stale_window: int
    recent_records: int
    recent_retained: int
    recent_new_features: int
    recent_crashes: int
    recent_timeouts: int
    profile_cups: int
    profile_pwg: int
    profile_images: int
    recommended_env: dict[str, str]
    recommended_command: str
    target_actions: dict[str, str]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_root": self.search_root,
            "run_dirs": self.run_dirs,
            "output_profile": self.output_profile,
            "expansion_level": self.expansion_level,
            "stale_window": self.stale_window,
            "recent_records": self.recent_records,
            "recent_retained": self.recent_retained,
            "recent_new_features": self.recent_new_features,
            "recent_crashes": self.recent_crashes,
            "recent_timeouts": self.recent_timeouts,
            "profile_cups": self.profile_cups,
            "profile_pwg": self.profile_pwg,
            "profile_images": self.profile_images,
            "recommended_env": self.recommended_env,
            "recommended_command": self.recommended_command,
            "target_actions": self.target_actions,
            "notes": self.notes,
        }


def build_auto_expand_plan(
    *,
    search_root: str | Path = "work",
    output_profile: str | Path = "work/template-feedback/auto-expand-feedback.json",
    max_runs: int = 8,
    max_cases_per_kind: int = 160,
    stale_window: int = 5000,
    duration_sec: int = 1200,
    workers: int = 10,
    timeout_sec: int = 5,
    max_run_gb: float = 10.0,
    skip_probe_rate: float = 0.01,
) -> AutoExpandPlan:
    runs = discover_campaign_runs(search_root, max_runs=max_runs)
    if not runs:
        raise ValueError(f"no campaign summaries found under {search_root}")

    profile = build_feedback_profile(runs, max_cases_per_kind=max_cases_per_kind)
    output_path = Path(output_profile)
    write_feedback_profile(profile, output_path)

    latest = runs[0]
    recent_records = _read_recent_timeline(latest, stale_window)
    latest_summary = _read_summary(latest)
    recent_retained = sum(1 for record in recent_records if record.get("retained_for_coverage"))
    recent_new_features = sum(_safe_int(record.get("new_feature_count")) for record in recent_records)
    recent_crashes = sum(1 for record in recent_records if record.get("crashed"))
    recent_timeouts = sum(1 for record in recent_records if record.get("timed_out"))
    expansion_level = _recommend_expansion_level(
        recent_count=len(recent_records),
        recent_retained=recent_retained,
        recent_new_features=recent_new_features,
    )
    env = {
        "SMT_FUZZER_TEMPLATE_FEEDBACK": str(output_path),
        "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": str(expansion_level),
        "SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS": "8",
        "SMT_FUZZER_HAZARD_SKIP_AFTER": "24",
        "SMT_FUZZER_SEMANTIC_SKIP_AFTER": "2",
        "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "1",
        "SMT_FUZZER_LOAD_LEGACY_SKIP_STATE": "1",
        "SMT_FUZZER_MAX_RUN_GB": f"{max_run_gb:g}",
        "SMT_FUZZER_SKIP_PROBE_RATE": f"{skip_probe_rate:g}",
    }
    command = _recommended_command(
        output_path=output_path,
        expansion_level=expansion_level,
        duration_sec=duration_sec,
        workers=workers,
        timeout_sec=timeout_sec,
        max_run_gb=max_run_gb,
        skip_probe_rate=skip_probe_rate,
    )
    notes = _notes(
        expansion_level=expansion_level,
        recent_count=len(recent_records),
        recent_retained=recent_retained,
        recent_new_features=recent_new_features,
        profile_cups=len(profile.cups),
        profile_pwg=len(profile.pwg),
        profile_images=len(profile.images),
    )
    return AutoExpandPlan(
        search_root=str(search_root),
        run_dirs=[str(path) for path in runs],
        output_profile=str(output_path),
        expansion_level=expansion_level,
        stale_window=stale_window,
        recent_records=len(recent_records),
        recent_retained=recent_retained,
        recent_new_features=recent_new_features,
        recent_crashes=recent_crashes,
        recent_timeouts=recent_timeouts,
        profile_cups=len(profile.cups),
        profile_pwg=len(profile.pwg),
        profile_images=len(profile.images),
        recommended_env=env,
        recommended_command=command,
        target_actions=_target_actions(latest_summary),
        notes=notes,
    )


def write_auto_expand_plan(plan: AutoExpandPlan, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def discover_campaign_runs(search_root: str | Path, *, max_runs: int = 8) -> list[Path]:
    root = Path(search_root)
    if not root.exists():
        return []
    candidates: list[tuple[float, Path]] = []
    for path in _iter_campaign_dirs(root, max_depth=3):
        summary_path = path / "summary.concise.json"
        if not summary_path.exists():
            continue
        try:
            candidates.append((summary_path.stat().st_mtime, path))
        except OSError:
            continue
    candidates.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    return [path for _, path in candidates[:max(1, max_runs)]]


def _iter_campaign_dirs(root: Path, *, max_depth: int) -> list[Path]:
    result: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        path, depth = stack.pop()
        if (path / "summary.concise.json").exists():
            result.append(path)
            continue
        if depth >= max_depth:
            continue
        try:
            children = [child for child in path.iterdir() if child.is_dir()]
        except OSError:
            continue
        for child in children:
            stack.append((child, depth + 1))
    return result


def _read_recent_timeline(run_dir: Path, limit: int) -> list[dict[str, Any]]:
    timeline_path = run_dir / "timeline.jsonl"
    if not timeline_path.exists():
        return []
    tail: deque[str] = deque(maxlen=max(1, limit))
    try:
        with timeline_path.open("r", encoding="utf-8", errors="replace") as handle:
            tail.extend(handle)
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in tail:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _read_summary(run_dir: Path) -> dict[str, Any]:
    summary_path = run_dir / "summary.concise.json"
    try:
        return json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _recommend_expansion_level(*, recent_count: int, recent_retained: int, recent_new_features: int) -> int:
    if recent_count <= 0:
        return 1
    retained_rate = recent_retained / max(1, recent_count)
    if recent_retained == 0 and recent_new_features == 0:
        return 2
    if retained_rate < 0.001:
        return 1
    return 0


def _target_actions(summary: dict[str, Any]) -> dict[str, str]:
    actions: dict[str, str] = {}
    target_stats = summary.get("target_stats", {})
    if not isinstance(target_stats, dict):
        return actions
    for target_id, raw_stats in sorted(target_stats.items()):
        if not isinstance(raw_stats, dict):
            continue
        completed = _safe_int(raw_stats.get("completed"))
        skipped = _safe_int(raw_stats.get("skipped"))
        retained = _safe_int(raw_stats.get("retained_cases"))
        timeouts = _safe_int(raw_stats.get("timeouts"))
        crashes = _safe_int(raw_stats.get("crashes"))
        if completed == 0 and skipped > 0:
            actions[str(target_id)] = "probe-runtime-suppressed-family"
            continue
        if completed > 0 and timeouts / max(1, completed) > 0.05:
            actions[str(target_id)] = "deprioritize-timeout-heavy-template"
            continue
        if completed > 0 and retained / max(1, completed) < 0.001:
            actions[str(target_id)] = "expand-template-neighborhood"
            continue
        if crashes > 0 and retained == 0:
            actions[str(target_id)] = "keep-skip-and-probe-lightly"
            continue
        actions[str(target_id)] = "continue-frontier-exploration"
    return actions


def _recommended_command(
    *,
    output_path: Path,
    expansion_level: int,
    duration_sec: int,
    workers: int,
    timeout_sec: int,
    max_run_gb: float,
    skip_probe_rate: float,
) -> str:
    env = {
        "SMT_FUZZER_TEMPLATE_FEEDBACK": str(output_path),
        "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": str(expansion_level),
        "SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS": "8",
        "SMT_FUZZER_HAZARD_SKIP_AFTER": "24",
        "SMT_FUZZER_SEMANTIC_SKIP_AFTER": "2",
        "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "1",
        "SMT_FUZZER_LOAD_LEGACY_SKIP_STATE": "1",
        "SMT_FUZZER_MAX_RUN_GB": f"{max_run_gb:g}",
        "SMT_FUZZER_SKIP_PROBE_RATE": f"{skip_probe_rate:g}",
    }
    env_part = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
    args = [
        "PYTHONPATH=src",
        "python3",
        "-m",
        "parser_fuzzers.cli",
        "multitarget-monitor",
        "--config",
        "configs/parser_targets_auto_hybrid.yaml",
        "--work-root",
        "work/auto-hybrid-campaign",
        "--workers",
        str(workers),
        "--timeout-sec",
        str(timeout_sec),
        "--duration-sec",
        str(duration_sec),
        "--max-run-gb",
        f"{max_run_gb:g}",
        "--discard-stdout",
        "--discovery-mode",
        "coverage",
        "--scheduler",
        "novelty",
        "--runtime-skip",
        "--auto-skip-state",
        "--auto-skip-root",
        "work",
        "--generalized-skip",
        "--family-skip-after",
        "12",
        "--skip-probe-rate",
        f"{skip_probe_rate:g}",
        "--prune-uninteresting",
    ]
    return f"{env_part} {' '.join(shlex.quote(arg) for arg in args)}"


def _notes(
    *,
    expansion_level: int,
    recent_count: int,
    recent_retained: int,
    recent_new_features: int,
    profile_cups: int,
    profile_pwg: int,
    profile_images: int,
) -> list[str]:
    notes = []
    if expansion_level > 0:
        notes.append("recent coverage yield is low; widen feedback template neighborhoods")
    else:
        notes.append("recent coverage yield is still useful; keep conservative neighborhoods")
    if profile_cups == 0:
        notes.append("no CUPS raster feedback seeds were found")
    if profile_pwg == 0:
        notes.append("no PWG raster feedback seeds were found")
    if profile_images == 0:
        notes.append("no image feedback seeds were found")
    notes.append(
        f"recent window: {recent_retained} retained / {recent_count} records, {recent_new_features} new features"
    )
    return notes


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
