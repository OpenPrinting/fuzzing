from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from parser_fuzzers.run_metrics import summarize_run_metrics


@dataclass(frozen=True)
class RunRow:
    campaign: str
    run_dir: str
    run_id: str
    elapsed_sec: float
    cases: int
    retained_cases: int
    coverage_features: int
    crashes: int
    unique_crashes: int
    repeat_crashes: int
    timeouts: int
    skipped: int
    retained_density: float
    crash_density: float
    features_per_min: float
    stop_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign,
            "run_dir": self.run_dir,
            "run_id": self.run_id,
            "elapsed_sec": self.elapsed_sec,
            "cases": self.cases,
            "retained_cases": self.retained_cases,
            "coverage_features": self.coverage_features,
            "crashes": self.crashes,
            "unique_crashes": self.unique_crashes,
            "repeat_crashes": self.repeat_crashes,
            "timeouts": self.timeouts,
            "skipped": self.skipped,
            "retained_density": self.retained_density,
            "crash_density": self.crash_density,
            "features_per_min": self.features_per_min,
            "stop_reason": self.stop_reason,
        }


def summarize_run_set(roots: list[str | Path]) -> dict[str, Any]:
    rows = [_row_from_metrics(campaign, run_dir) for campaign, run_dir in _find_run_dirs(roots)]
    rows.sort(key=lambda row: (row.campaign, row.run_id, row.run_dir))
    campaigns: dict[str, list[RunRow]] = {}
    for row in rows:
        campaigns.setdefault(row.campaign, []).append(row)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roots": [str(Path(root)) for root in roots],
        "run_count": len(rows),
        "aggregate": _aggregate_rows(rows),
        "campaigns": {name: _aggregate_rows(items) for name, items in sorted(campaigns.items())},
        "runs": [row.to_dict() for row in rows],
        "notes": [
            "coverage_features is summed from each run's within-run new feature count; it is not globally deduplicated across runs.",
            "unique_crashes is summed from run summaries and may count the same crash signature again across separate runs.",
            "Use LLVM profraw/llvm-cov or AFL++ edge data for globally comparable source/edge coverage.",
        ],
    }


def write_run_set_metrics(payload: dict[str, Any], output_json: str | Path, output_md: str | Path | None = None) -> None:
    json_path = Path(output_json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output_md:
        Path(output_md).write_text(render_run_set_markdown(payload), encoding="utf-8")


def render_run_set_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Long-Run Metrics {payload.get('generated_at', '')}",
        "",
        "## Aggregate",
        "",
        _aggregate_table(payload.get("aggregate", {})),
        "",
        "## Campaigns",
        "",
        "| Campaign | Runs | Hours | Cases | Retained | Features sum | Features/hour | Crashes | Unique crashes sum | Crash density |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, stats in payload.get("campaigns", {}).items():
        lines.append(
            f"| {name} | {stats.get('run_count', 0)} | {_fmt(stats.get('elapsed_hours', 0))} | "
            f"{stats.get('cases', 0)} | {stats.get('retained_cases', 0)} | "
            f"{stats.get('coverage_features_sum', 0)} | {_fmt(stats.get('features_per_hour', 0))} | "
            f"{stats.get('crashes', 0)} | {stats.get('unique_crashes_sum', 0)} | "
            f"{_fmt(stats.get('crash_density', 0))} |"
        )
    lines.extend(
        [
            "",
            "## Top Feature Runs",
            "",
            "| Campaign | Run | Minutes | Cases | Features | Features/min | Crashes | Crash density |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    top_runs = sorted(payload.get("runs", []), key=lambda row: row.get("coverage_features", 0), reverse=True)[:20]
    for row in top_runs:
        lines.append(
            f"| {row.get('campaign', '')} | {row.get('run_id', '')} | "
            f"{_fmt(float(row.get('elapsed_sec', 0)) / 60.0)} | {row.get('cases', 0)} | "
            f"{row.get('coverage_features', 0)} | {_fmt(row.get('features_per_min', 0))} | "
            f"{row.get('crashes', 0)} | {_fmt(row.get('crash_density', 0))} |"
        )
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {note}" for note in payload.get("notes", []))
    lines.append("")
    return "\n".join(lines)


def _find_run_dirs(roots: list[str | Path]) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for raw_root in roots:
        root = Path(raw_root)
        campaign = root.name
        if _is_run_dir(root):
            resolved = root.resolve()
            if resolved not in seen:
                found.append((campaign, root))
                seen.add(resolved)
            continue
        if not root.exists():
            continue
        for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
            if not _is_run_dir(run_dir):
                continue
            resolved = run_dir.resolve()
            if resolved in seen:
                continue
            found.append((campaign, run_dir))
            seen.add(resolved)
    return found


def _is_run_dir(path: Path) -> bool:
    return (path / "timeline.jsonl").exists() and (
        (path / "summary.concise.json").exists()
        or (path / "summary.json").exists()
        or (path / "run_manifest.json").exists()
    )


def _row_from_metrics(campaign: str, run_dir: Path) -> RunRow:
    metrics = summarize_run_metrics(run_dir)
    run = metrics.get("run", {})
    derived = metrics.get("derived", {})
    dedup = metrics.get("dedup", {})
    crashes = _int(run.get("crashes"))
    unique = max(_int(run.get("unique_crashes")), _int(dedup.get("unique_crash_signatures")))
    return RunRow(
        campaign=campaign,
        run_dir=str(run_dir),
        run_id=str(run.get("run_id") or run_dir.name),
        elapsed_sec=_float(run.get("elapsed_sec")),
        cases=_int(run.get("cases")),
        retained_cases=_int(run.get("retained_cases")),
        coverage_features=_int(run.get("coverage_features")),
        crashes=crashes,
        unique_crashes=unique,
        repeat_crashes=max(0, crashes - unique),
        timeouts=_int(run.get("timeouts")),
        skipped=_int(run.get("skipped")),
        retained_density=_float(derived.get("retained_density")),
        crash_density=_float(derived.get("crash_density")),
        features_per_min=_float(derived.get("features_per_min")),
        stop_reason=str(run.get("stop_reason") or ""),
    )


def _aggregate_rows(rows: list[RunRow]) -> dict[str, Any]:
    elapsed_sec = sum(row.elapsed_sec for row in rows)
    cases = sum(row.cases for row in rows)
    retained = sum(row.retained_cases for row in rows)
    features = sum(row.coverage_features for row in rows)
    crashes = sum(row.crashes for row in rows)
    unique = sum(row.unique_crashes for row in rows)
    return {
        "run_count": len(rows),
        "elapsed_sec": round(elapsed_sec, 3),
        "elapsed_hours": round(elapsed_sec / 3600.0, 3),
        "cases": cases,
        "cases_per_sec": _rate(cases, elapsed_sec),
        "retained_cases": retained,
        "retained_density": _ratio(retained, cases),
        "coverage_features_sum": features,
        "features_per_hour": _rate(features, elapsed_sec / 3600.0),
        "crashes": crashes,
        "unique_crashes_sum": unique,
        "repeat_crashes_estimate": max(0, crashes - unique),
        "crash_density": _ratio(crashes, cases),
        "timeouts": sum(row.timeouts for row in rows),
        "skipped": sum(row.skipped for row in rows),
        "max_run_coverage_features": max((row.coverage_features for row in rows), default=0),
        "max_run_features_per_min": max((row.features_per_min for row in rows), default=0.0),
    }


def _aggregate_table(stats: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"- Runs: `{stats.get('run_count', 0)}`",
            f"- Elapsed hours: `{_fmt(stats.get('elapsed_hours', 0))}`",
            f"- Cases: `{stats.get('cases', 0)}`",
            f"- Retained cases: `{stats.get('retained_cases', 0)}`",
            f"- Coverage features sum: `{stats.get('coverage_features_sum', 0)}`",
            f"- Features/hour: `{_fmt(stats.get('features_per_hour', 0))}`",
            f"- Crashes: `{stats.get('crashes', 0)}`",
            f"- Unique crashes sum: `{stats.get('unique_crashes_sum', 0)}`",
            f"- Crash density: `{_fmt(stats.get('crash_density', 0))}`",
        ]
    )


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def _rate(value: int, elapsed: float) -> float:
    if elapsed <= 0.0:
        return 0.0
    return round(value / elapsed, 3)


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
