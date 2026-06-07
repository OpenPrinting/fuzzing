from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from parser_fuzzers.crash_avoidance import generalized_crash_avoidance_enabled, preferred_crash_avoidance_profile
from parser_fuzzers.dimension_expander import expand_image_goals
from parser_fuzzers.format_specs import ImageGoal, image_goals_for_target


@dataclass(frozen=True)
class OutputFeedbackProfile:
    source_run_dirs: tuple[str, ...]
    format_counts: dict[str, int]
    structure_counts: dict[str, int]
    objective_counts: dict[str, int]
    objective_output_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_run_dirs": list(self.source_run_dirs),
            "format_counts": self.format_counts,
            "structure_counts": self.structure_counts,
            "objective_counts": self.objective_counts,
            "objective_output_counts": self.objective_output_counts,
        }


def build_output_feedback_profile(run_dir: str | Path | Iterable[str | Path]) -> OutputFeedbackProfile:
    roots = _normalize_run_dirs(run_dir)
    formats: Counter[str] = Counter()
    structures: Counter[str] = Counter()
    objectives: Counter[str] = Counter()
    objective_outputs: Counter[str] = Counter()
    for root in roots:
        for record in _iter_timeline(root):
            target_id = str(record.get("target_id") or "")
            objective = _record_objective(record)
            if objective:
                objectives[f"{target_id}|{objective}"] += 1
            output = ((record.get("semantic_shape") or {}).get("output") or {})
            output_format = str(output.get("format") or "")
            structure = str(output.get("structure") or "")
            if output_format:
                formats[f"{target_id}|{output_format}"] += 1
            if structure:
                structures[f"{target_id}|{structure}"] += 1
            if objective and output_format and output_format != "empty":
                objective_outputs[f"{target_id}|{objective}|{output_format}"] += 1
    return OutputFeedbackProfile(
        source_run_dirs=tuple(str(root) for root in roots),
        format_counts=dict(sorted(formats.items())),
        structure_counts=dict(sorted(structures.items())),
        objective_counts=dict(sorted(objectives.items())),
        objective_output_counts=dict(sorted(objective_outputs.items())),
    )


def write_output_feedback_profile(profile: OutputFeedbackProfile, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_output_feedback_profile(path: str | Path) -> OutputFeedbackProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return OutputFeedbackProfile(
        source_run_dirs=tuple(str(item) for item in data.get("source_run_dirs", [])),
        format_counts={str(k): int(v) for k, v in dict(data.get("format_counts", {})).items()},
        structure_counts={str(k): int(v) for k, v in dict(data.get("structure_counts", {})).items()},
        objective_counts={str(k): int(v) for k, v in dict(data.get("objective_counts", {})).items()},
        objective_output_counts={
            str(k): int(v) for k, v in dict(data.get("objective_output_counts", {})).items()
        },
    )


def choose_image_goal(
    *,
    target_id: str,
    slot: int,
    profile: OutputFeedbackProfile | None = None,
) -> ImageGoal:
    avoidance = preferred_crash_avoidance_profile()
    generalized_avoidance = generalized_crash_avoidance_enabled()
    goals = expand_image_goals(
        target_id=target_id,
        goals=image_goals_for_target(target_id),
        profile=profile,
        slot=slot,
    )
    if not profile and not avoidance.hazards:
        return goals[slot % len(goals)]

    def rank(goal: ImageGoal) -> tuple[int, int, int, int, str]:
        objective_key = f"{target_id}|{goal.name}"
        output_key = f"{target_id}|{goal.name}|{goal.output_format}"
        format_key = f"{target_id}|{goal.output_format}"
        objective_output_count = profile.objective_output_counts.get(output_key, 0) if profile else 0
        objective_count = profile.objective_counts.get(objective_key, 0) if profile else 0
        format_count = profile.format_counts.get(format_key, 0) if profile else 0
        avoidance_penalty = avoidance.goal_penalty(
            target_id,
            goal,
            generalized=generalized_avoidance,
        )
        salt = _stable_int(f"{target_id}|{goal.name}|{slot}") % 17
        return (avoidance_penalty, objective_output_count, objective_count, format_count + salt, goal.name)

    return min(goals, key=rank)


def _normalize_run_dirs(run_dir: str | Path | Iterable[str | Path]) -> list[Path]:
    if isinstance(run_dir, (str, Path)):
        return [Path(run_dir)]
    roots = [Path(item) for item in run_dir]
    return roots or [Path(".")]


def _iter_timeline(root: Path):
    timeline = root / "timeline.jsonl"
    if not timeline.exists():
        return
    with timeline.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _record_objective(record: dict[str, Any]) -> str:
    description = str(record.get("document_description") or "")
    marker = " via "
    if marker not in description:
        return ""
    objective = description.split(marker, 1)[1].split("/", 1)[0].strip()
    if ":" in objective:
        prefix, suffix = objective.split(":", 1)
        if prefix in {"pdf", "postscript", "cups-raster", "pwg-raster"}:
            return suffix
    return objective


def _stable_int(value: str) -> int:
    total = 0
    for char in value:
        total = (total * 131 + ord(char)) & 0xFFFFFFFF
    return total
