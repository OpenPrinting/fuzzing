from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from parser_fuzzers.multitarget_runner import _run_dir_size_bytes


def recover_run_summary(run_dir: str | Path) -> dict[str, Any]:
    root = Path(run_dir)
    manifest = _read_json(root / "run_manifest.json")
    timeline_path = root / "timeline.jsonl"
    if not timeline_path.exists():
        raise FileNotFoundError(f"missing timeline.jsonl in {root}")

    target_stats = _initial_target_stats(manifest)
    skip_counts: dict[str, int] = {}
    oracle_counts: dict[str, int] = {}
    cases = 0
    crashes = 0
    reached = 0
    valid_ppds = 0
    timeouts = 0
    skipped = 0
    retained_cases = 0
    coverage_features = 0
    unique_crashes = 0
    repeat_crashes = 0

    for record in _iter_timeline(timeline_path):
        target_id = str(record.get("target_id", "unknown"))
        stats = target_stats.setdefault(target_id, _empty_target_stats())
        if record.get("skipped"):
            skipped += 1
            reason = str(record.get("skip_reason") or "skipped")
            skip_counts[reason] = skip_counts.get(reason, 0) + 1
            stats["skipped"] += 1
            if reason.startswith("runtime-known-crash-"):
                stats["runtime_suppressed"] += 1
            continue

        cases += 1
        stats["submitted"] += 1
        stats["completed"] += 1
        oracle = str(record.get("oracle") or "none")
        oracle_counts[oracle] = oracle_counts.get(oracle, 0) + 1
        if record.get("crashed"):
            crashes += 1
            stats["crashes"] += 1
            if record.get("new_crash_signature") is True:
                unique_crashes += 1
                stats["unique_crashes"] += 1
            elif record.get("new_crash_signature") is False:
                repeat_crashes += 1
                stats["repeat_crashes"] += 1
        if record.get("timed_out"):
            timeouts += 1
            stats["timeouts"] += 1
        if record.get("reached_expected_filter"):
            reached += 1
        if record.get("cupstestppd_ok"):
            valid_ppds += 1
        if record.get("retained_for_coverage"):
            retained_cases += 1
            stats["retained_cases"] += 1
        new_feature_count = _safe_int(record.get("new_feature_count", 0))
        coverage_features += new_feature_count
        stats["new_features"] += new_feature_count

    summary = {
        "run_id": str(manifest.get("run_id") or root.name),
        "work_dir": str(root),
        "config_path": str(manifest.get("config_path") or ""),
        "duration_budget_sec": _optional_int(manifest.get("duration_sec")),
        "elapsed_sec": _estimate_elapsed_sec(root, timeline_path),
        "workers": _safe_int(manifest.get("workers", 0)),
        "timeout_sec": _safe_int(manifest.get("timeout_sec", 0)),
        "max_run_bytes": _safe_int(manifest.get("max_run_bytes", 0)),
        "run_dir_bytes": _run_dir_size_bytes(root),
        "stop_reason": "recovered-missing-summary",
        "targets": len(manifest.get("targets") or target_stats),
        "cases": cases,
        "crashes": crashes,
        "reached": reached,
        "valid_ppds": valid_ppds,
        "timeouts": timeouts,
        "skipped": skipped,
        "pruned_cases": 0,
        "skip_counts": dict(sorted(skip_counts.items())),
        "scheduler": str(manifest.get("scheduler") or ""),
        "min_target_share": float(manifest.get("min_target_share") or 0.0),
        "max_target_share": float(manifest.get("max_target_share") or 1.0),
        "runtime_skip_enabled": bool(manifest.get("runtime_skip")),
        "auto_skip_state_enabled": bool(manifest.get("auto_skip_state")),
        "auto_skip_search_root": str(manifest.get("auto_skip_search_root") or ""),
        "runtime_suppressed_shapes": 0,
        "seeded_runtime_suppressed_shapes": _safe_int(manifest.get("seeded_runtime_suppressed_shapes", 0)),
        "runtime_suppressed_families": 0,
        "seeded_runtime_suppressed_families": _safe_int(manifest.get("seeded_runtime_suppressed_families", 0)),
        "generalized_skip_enabled": bool(manifest.get("generalized_skip")),
        "family_skip_after": _safe_int(manifest.get("family_skip_after", 0)),
        "skip_probe_rate": float(manifest.get("skip_probe_rate") or 0.0),
        "skip_only_stop_after": _safe_int(manifest.get("skip_only_stop_after", 0)),
        "stagnation_stop_after_sec": _safe_int(manifest.get("stagnation_stop_after_sec", 0)),
        "seed_skip_state_path": str(manifest.get("seed_skip_state_path") or ""),
        "target_stats": target_stats,
        "retained_cases": retained_cases,
        "coverage_features": coverage_features,
        "unique_crashes": unique_crashes,
        "repeat_crashes": repeat_crashes,
        "oracle_counts": dict(sorted(oracle_counts.items())),
        "recovered": True,
        "summary_source": "timeline.jsonl",
    }
    _merge_discovery_state(root, summary)

    (root / "summary.concise.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "summary.json").write_text(
        json.dumps(
            {
                **summary,
                "summary_mode": "concise",
                "results_omitted": True,
                "results_source": "timeline.jsonl",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary


def _merge_discovery_state(root: Path, summary: dict[str, Any]) -> None:
    state_path = root / "discovery_state.json"
    if not state_path.exists():
        return
    state = _read_json(state_path)
    summary["runtime_suppressed_shapes"] = _safe_int(state.get("runtime_suppressed_shapes", 0))
    summary["runtime_suppressed_families"] = _safe_int(state.get("runtime_suppressed_families", 0))


def _initial_target_stats(manifest: dict[str, Any]) -> dict[str, dict[str, int]]:
    stats = {}
    for item in manifest.get("targets") or []:
        target_id = str(item.get("id") or "")
        if target_id:
            stats[target_id] = _empty_target_stats()
    return stats


def _empty_target_stats() -> dict[str, int]:
    return {
        "submitted": 0,
        "completed": 0,
        "skipped": 0,
        "retained_cases": 0,
        "new_features": 0,
        "crashes": 0,
        "unique_crashes": 0,
        "repeat_crashes": 0,
        "timeouts": 0,
        "runtime_suppressed": 0,
    }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _iter_timeline(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield json.loads(stripped)


def _estimate_elapsed_sec(root: Path, timeline_path: Path) -> float:
    start_path = root / "run_manifest.json"
    try:
        start = start_path.stat().st_mtime if start_path.exists() else root.stat().st_mtime
        return round(max(0.0, timeline_path.stat().st_mtime - start), 3)
    except OSError:
        return 0.0


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return _safe_int(value)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
