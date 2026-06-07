from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def summarize_run_metrics(
    run_dir: str | Path,
    *,
    afl_output_dir: str | Path | None = None,
    llvm_coverage_json: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(run_dir)
    afl_stats = _afl_stats(Path(afl_output_dir)) if afl_output_dir else {}
    summary = _read_json(root / "summary.concise.json") or _read_json(root / "summary.json")
    if not summary and afl_stats.get("status") == "ok":
        summary = _summary_from_afl_stats(afl_stats)
    dedup = _read_json(root / "dedup.json") or _read_json(root / "crash_dedup.json")
    timeline = _timeline_counts(root / "timeline.jsonl")
    elapsed_sec = _safe_float(summary.get("elapsed_sec"))
    cases = _safe_int(summary.get("cases"))
    retained = _safe_int(summary.get("retained_cases"))
    crashes = _safe_int(summary.get("crashes"))
    features = _safe_int(summary.get("coverage_features"))
    unique_summary = _safe_int(summary.get("unique_crashes"))
    unique_dedup = _safe_int(dedup.get("unique_crashes"))
    unique_effective = unique_dedup or unique_summary
    run_dir_bytes = _safe_int(summary.get("run_dir_bytes"))

    payload: dict[str, Any] = {
        "schema_version": "standard-run-metrics-v1",
        "run_dir": str(root),
        "run": {
            "run_id": summary.get("run_id", ""),
            "elapsed_sec": elapsed_sec,
            "cases": cases,
            "retained_cases": retained,
            "coverage_features": features,
            "crashes": crashes,
            "unique_crashes": unique_summary,
            "timeouts": _safe_int(summary.get("timeouts")),
            "skipped": _safe_int(summary.get("skipped")),
            "pruned_cases": _safe_int(summary.get("pruned_cases")),
            "targets": _safe_int(summary.get("targets")),
            "run_dir_bytes": run_dir_bytes,
            "stop_reason": summary.get("stop_reason", ""),
        },
        "derived": {
            "crash_density": _ratio(crashes, cases),
            "retained_density": _ratio(retained, cases),
            "cases_per_sec": _per_sec(cases, elapsed_sec),
            "retained_per_min": _per_min(retained, elapsed_sec),
            "features_per_min": _per_min(features, elapsed_sec),
            "features_per_hour": _per_hour(features, elapsed_sec),
            "crashes_per_hour": _per_hour(crashes, elapsed_sec),
            "timeline_records": timeline["records"],
            "z3_structure_avoid_records": timeline["z3_structure_avoid_records"],
            "new_crash_signature_records": timeline["new_crash_signature_records"],
        },
        "dedup": {
            "crash_records": _safe_int(dedup.get("crash_records")),
            "unique_crash_signatures": _safe_int(dedup.get("unique_crashes")),
            "clusters": _cluster_summary(dedup.get("clusters", [])),
        },
        "standard": {
            "elapsed_sec": elapsed_sec,
            "elapsed_hours": round(elapsed_sec / 3600.0, 6) if elapsed_sec > 0 else 0.0,
            "execs_done": cases,
            "execs_per_sec": _per_sec(cases, elapsed_sec),
            "corpus_count": retained,
            "corpus_density": _ratio(retained, cases),
            "coverage_features": features,
            "coverage_features_per_min": _per_min(features, elapsed_sec),
            "coverage_features_per_hour": _per_hour(features, elapsed_sec),
            "crashes": crashes,
            "unique_crashes": unique_effective,
            "summary_unique_crashes": unique_summary,
            "dedup_unique_crashes": unique_dedup,
            "repeat_crashes_estimate": max(0, crashes - unique_effective),
            "crash_density": _ratio(crashes, cases),
            "crashes_per_hour": _per_hour(crashes, elapsed_sec),
            "timeouts": _safe_int(summary.get("timeouts")),
            "skipped": _safe_int(summary.get("skipped")),
            "pruned_cases": _safe_int(summary.get("pruned_cases")),
            "targets": _safe_int(summary.get("targets")),
            "run_dir_bytes": run_dir_bytes,
            "run_dir_gb": round(run_dir_bytes / (1024.0**3), 6) if run_dir_bytes else 0.0,
            "stop_reason": str(summary.get("stop_reason", "")),
        },
        "target_stats": _target_stats_summary(summary.get("target_stats", {})),
    }
    if afl_output_dir:
        payload["afl"] = afl_stats
    if llvm_coverage_json:
        payload["llvm_cov"] = _llvm_coverage_totals(Path(llvm_coverage_json))
    return payload


def write_run_metrics(payload: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_standard_run_metrics(
    run_dir: str | Path,
    *,
    output_path: str | Path | None = None,
    afl_output_dir: str | Path | None = None,
    llvm_coverage_json: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(run_dir)
    payload = summarize_run_metrics(
        root,
        afl_output_dir=afl_output_dir,
        llvm_coverage_json=llvm_coverage_json,
    )
    write_run_metrics(payload, output_path or root / "standard_metrics.json")
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _timeline_counts(path: Path) -> dict[str, int]:
    counts = {
        "records": 0,
        "z3_structure_avoid_records": 0,
        "new_crash_signature_records": 0,
    }
    if not path.exists():
        return counts
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            counts["records"] += 1
            if "z3-structure-avoid" in line:
                counts["z3_structure_avoid_records"] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("new_crash_signature") is True:
                counts["new_crash_signature_records"] += 1
    return counts


def _cluster_summary(clusters: Any) -> list[dict[str, Any]]:
    if not isinstance(clusters, list):
        return []
    rows = []
    for item in clusters[:20]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "target_id": item.get("target_id", ""),
                "count": _safe_int(item.get("count")),
                "signature": item.get("signature", ""),
                "representative_work_dir": item.get("representative_work_dir", ""),
            }
        )
    return rows


def _target_stats_summary(raw_stats: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_stats, dict):
        return {}
    summary: dict[str, dict[str, Any]] = {}
    for target_id, stats in raw_stats.items():
        if not isinstance(stats, dict):
            continue
        completed = _safe_int(stats.get("completed"))
        retained = _safe_int(stats.get("retained_cases"))
        crashes = _safe_int(stats.get("crashes"))
        summary[str(target_id)] = {
            "completed": completed,
            "retained_cases": retained,
            "crashes": crashes,
            "timeouts": _safe_int(stats.get("timeouts")),
            "runtime_suppressed": _safe_int(stats.get("runtime_suppressed")),
            "retained_density": _ratio(retained, completed),
            "crash_density": _ratio(crashes, completed),
        }
    return dict(sorted(summary.items()))


def _afl_stats(output_dir: Path) -> dict[str, str]:
    stats_path = _find_afl_stats(output_dir)
    if not stats_path:
        return {"status": "missing-fuzzer-stats", "output_dir": str(output_dir)}
    stats: dict[str, str] = {"status": "ok", "fuzzer_stats": str(stats_path)}
    for line in stats_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def _summary_from_afl_stats(stats: dict[str, str]) -> dict[str, Any]:
    return {
        "run_id": Path(stats.get("fuzzer_stats", "")).parent.name,
        "elapsed_sec": _safe_float(stats.get("run_time")),
        "cases": _safe_int(stats.get("execs_done")),
        "retained_cases": _safe_int(stats.get("corpus_count")),
        "coverage_features": _safe_int(stats.get("edges_found")),
        "crashes": _safe_int(stats.get("saved_crashes")),
        "unique_crashes": _safe_int(stats.get("saved_crashes")),
        "timeouts": _safe_int(stats.get("saved_hangs")),
        "skipped": 0,
        "pruned_cases": 0,
        "targets": 1,
        "run_dir_bytes": _run_dir_size_bytes(Path(stats.get("fuzzer_stats", ".")).parent),
        "stop_reason": "afl++",
        "target_stats": {},
    }


def _find_afl_stats(output_dir: Path) -> Path | None:
    candidates = [output_dir / "default" / "fuzzer_stats", output_dir / "fuzzer_stats"]
    candidates.extend(sorted(output_dir.glob("*/fuzzer_stats")))
    for path in candidates:
        if path.exists():
            return path
    return None


def _run_dir_size_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _llvm_coverage_totals(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    totals = payload.get("data", [{}])[0].get("totals", {}) if payload else {}
    return {
        "status": "ok" if totals else "missing-totals",
        "coverage_json": str(path),
        "totals": totals,
    }


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def _per_min(value: int, elapsed_sec: float) -> float:
    if elapsed_sec <= 0.0:
        return 0.0
    return round(value * 60.0 / elapsed_sec, 3)


def _per_hour(value: int, elapsed_sec: float) -> float:
    if elapsed_sec <= 0.0:
        return 0.0
    return round(value * 3600.0 / elapsed_sec, 3)


def _per_sec(value: int, elapsed_sec: float) -> float:
    if elapsed_sec <= 0.0:
        return 0.0
    return round(value / elapsed_sec, 3)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
