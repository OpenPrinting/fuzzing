from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def summarize_loop_metrics(campaign_dir: str | Path) -> dict[str, Any]:
    root = Path(campaign_dir)
    manifest = _read_json(root / "loop_manifest.json")
    template_metrics = _read_json(Path(manifest.get("template_run", "")) / "standard_metrics.json")
    feedback_template_metrics = _read_json(Path(manifest.get("feedback_run", "")) / "standard_metrics.json")
    afl_metrics = _read_json(root / "afl-standard-metrics.json")
    feedback_profile = _read_json(root / "feedback-profile-build.json")
    seed_export = _read_json(root / "seed-export.json")
    afl_import = _summarize_afl_import(_read_json(root / "afl-import.json"))

    return {
        "schema_version": "template-afl-loop-metrics-v1",
        "campaign_dir": str(root),
        "manifest": manifest,
        "seed_export": _summarize_seed_export(seed_export),
        "template_metrics": template_metrics,
        "afl_metrics": afl_metrics,
        "afl_import": afl_import,
        "feedback_profile": feedback_profile,
        "feedback_template_metrics": feedback_template_metrics,
        "summary": _loop_summary(template_metrics, afl_metrics, feedback_template_metrics),
    }


def write_loop_metrics(payload: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_standard_loop_metrics(
    campaign_dir: str | Path,
    *,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(campaign_dir)
    payload = summarize_loop_metrics(root)
    write_loop_metrics(payload, output_path or root / "loop_standard_metrics.json")
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _standard(metrics: dict[str, Any]) -> dict[str, Any]:
    standard = metrics.get("standard")
    return standard if isinstance(standard, dict) else {}


def _loop_summary(
    template_metrics: dict[str, Any],
    afl_metrics: dict[str, Any],
    feedback_template_metrics: dict[str, Any],
) -> dict[str, Any]:
    template = _standard(template_metrics)
    afl = _standard(afl_metrics)
    feedback = _standard(feedback_template_metrics)
    return {
        "template_execs_done": _safe_int(template.get("execs_done")),
        "template_features": _safe_int(template.get("coverage_features")),
        "template_corpus_count": _safe_int(template.get("corpus_count")),
        "afl_execs_done": _safe_int(afl.get("execs_done")),
        "afl_edges_found": _safe_int(afl.get("coverage_features")),
        "afl_corpus_count": _safe_int(afl.get("corpus_count")),
        "afl_crashes": _safe_int(afl.get("crashes")),
        "afl_hangs": _safe_int(afl.get("timeouts")),
        "feedback_template_execs_done": _safe_int(feedback.get("execs_done")),
        "feedback_template_features": _safe_int(feedback.get("coverage_features")),
        "feedback_template_corpus_count": _safe_int(feedback.get("corpus_count")),
        "feedback_feature_delta_vs_template": _safe_int(feedback.get("coverage_features"))
        - _safe_int(template.get("coverage_features")),
        "feedback_corpus_delta_vs_template": _safe_int(feedback.get("corpus_count"))
        - _safe_int(template.get("corpus_count")),
    }


def _summarize_seed_export(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "exported": _safe_int(payload.get("exported")),
        "targets": payload.get("targets", []),
        "extensions": payload.get("extensions", []),
        "exported_by_target": payload.get("exported_by_target", {}),
        "output_dir": payload.get("output_dir", ""),
    }


def _summarize_afl_import(payload: dict[str, Any]) -> dict[str, Any]:
    imported = payload.get("imported", [])
    if not isinstance(imported, list):
        imported = []
    source_counts: dict[str, int] = {}
    for item in imported:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
    return {
        "imported": len(imported),
        "crashes_imported": _safe_int(payload.get("crashes_imported")),
        "duplicates_skipped": _safe_int(payload.get("duplicates_skipped")),
        "source_counts": dict(sorted(source_counts.items())),
        "afl_instance_dir": payload.get("afl_instance_dir", ""),
    }


def _safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
