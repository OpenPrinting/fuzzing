from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from parser_fuzzers.format_specs import ImageGoal


@dataclass(frozen=True)
class CrashHazard:
    target_id: str
    ppd_kind: str
    document_kind: str
    image_format: str
    objective: str
    payload: str
    interlace: int | None
    signature: str
    raw: str

    def matches_target(self, target_id: str) -> bool:
        return _same_or_derived_target(self.target_id, target_id)

    def matches_goal(self, target_id: str, goal: ImageGoal) -> bool:
        if not self.matches_target(target_id):
            return False
        if self.image_format and self.image_format not in goal.allowed_formats:
            return False
        goal_objectives = {goal.name, f"{goal.output_format}:{goal.name}"}
        if self.objective in goal_objectives:
            return True
        if ":" in self.objective and self.objective.split(":", 1)[1] == goal.name:
            return True
        return False


@dataclass(frozen=True)
class CrashAvoidanceProfile:
    source_path: str
    hazards: tuple[CrashHazard, ...]

    def hazards_for_goal(self, target_id: str, goal: ImageGoal) -> tuple[CrashHazard, ...]:
        return tuple(hazard for hazard in self.hazards if hazard.matches_goal(target_id, goal))

    def generalized_hazards_for_goal(self, target_id: str, goal: ImageGoal) -> tuple[CrashHazard, ...]:
        return tuple(
            hazard
            for hazard in self.hazards
            if hazard.matches_target(target_id) and hazard.image_format in goal.allowed_formats
        )

    def goal_penalty(self, target_id: str, goal: ImageGoal, *, generalized: bool = False) -> int:
        exact = self.hazards_for_goal(target_id, goal)
        if not generalized:
            return len(exact) * 100
        seen = {hazard.raw for hazard in exact}
        generalized_count = sum(
            1 for hazard in self.generalized_hazards_for_goal(target_id, goal) if hazard.raw not in seen
        )
        return len(exact) * 100 + generalized_count * 10

    def target_hazard_count(self, target_id: str) -> int:
        return sum(1 for hazard in self.hazards if hazard.matches_target(target_id))

    def blocks_exact(
        self,
        *,
        target_id: str,
        objective: str,
        image_format: str,
        payload: str,
        interlace: int,
    ) -> bool:
        objective_suffix = objective.split(":", 1)[1] if ":" in objective else objective
        for hazard in self.hazards:
            if not hazard.matches_target(target_id):
                continue
            hazard_suffix = hazard.objective.split(":", 1)[1] if ":" in hazard.objective else hazard.objective
            if hazard_suffix != objective_suffix and hazard.objective != objective:
                continue
            if hazard.image_format != image_format:
                continue
            if hazard.payload != payload:
                continue
            if hazard.interlace is not None and hazard.interlace != interlace:
                continue
            return True
        return False

    def blocks_generalized(
        self,
        *,
        target_id: str,
        image_format: str,
        payload: str,
        interlace: int,
    ) -> bool:
        for hazard in self.hazards:
            if not hazard.matches_target(target_id):
                continue
            if hazard.image_format != image_format:
                continue
            if hazard.payload != payload:
                continue
            if hazard.interlace is not None and hazard.interlace != interlace:
                continue
            return True
        return False


EMPTY_PROFILE = CrashAvoidanceProfile(source_path="", hazards=())


def preferred_crash_avoidance_profile() -> CrashAvoidanceProfile:
    if not _enabled():
        return EMPTY_PROFILE
    state = os.environ.get("SMT_FUZZER_CRASH_AVOIDANCE_STATE", "auto").strip()
    root = os.environ.get("SMT_FUZZER_CRASH_AVOIDANCE_ROOT", "work").strip() or "work"
    return _load_cached(state, root)


def generalized_crash_avoidance_enabled() -> bool:
    return os.environ.get("SMT_FUZZER_CRASH_AVOIDANCE_GENERALIZE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@lru_cache(maxsize=16)
def _load_cached(state: str, root: str) -> CrashAvoidanceProfile:
    state_path = _resolve_state_path(state, root)
    if not state_path:
        return EMPTY_PROFILE
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return EMPTY_PROFILE
    hazards = tuple(_iter_hazards(payload))
    return CrashAvoidanceProfile(source_path=str(state_path), hazards=hazards)


def _iter_hazards(payload: dict[str, Any]) -> list[CrashHazard]:
    hazards: list[CrashHazard] = []
    for item in payload.get("suppressed_case_hazards", []):
        if not isinstance(item, dict):
            continue
        raw = str(item.get("hazard") or "")
        signature = str(item.get("signature") or "")
        fields = _parse_hazard_fields(raw)
        target_id = fields.get("target", "")
        image_format = fields.get("fmt", "")
        objective = fields.get("objective", "")
        if not target_id or not image_format or not objective:
            continue
        hazards.append(
            CrashHazard(
                target_id=target_id,
                ppd_kind=fields.get("ppd", ""),
                document_kind=fields.get("doc", ""),
                image_format=image_format,
                objective=objective,
                payload=fields.get("payload", ""),
                interlace=_safe_int(fields.get("interlace")),
                signature=signature,
                raw=raw,
            )
        )
    return hazards


def _parse_hazard_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in raw.split("|"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        fields[key] = value
    return fields


def _resolve_state_path(state: str, root: str) -> Path | None:
    if state and state != "auto":
        path = Path(state)
        return path if path.exists() else None
    return _find_latest_state(Path(root))


def _find_latest_state(root: Path) -> Path | None:
    if not root.exists():
        return None
    candidates: list[tuple[float, Path]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        path, depth = stack.pop()
        state = path / "discovery_state.json"
        if state.exists() and _state_has_hazards(state):
            try:
                candidates.append((state.stat().st_mtime, state))
            except OSError:
                pass
        if depth >= 4:
            continue
        try:
            children = [child for child in path.iterdir() if child.is_dir()]
        except OSError:
            continue
        for child in children:
            stack.append((child, depth + 1))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    return candidates[0][1]


def _state_has_hazards(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(payload.get("suppressed_case_hazards"))


def _enabled() -> bool:
    return os.environ.get("SMT_FUZZER_CRASH_AVOIDANCE", "").strip().lower() in {"1", "true", "yes", "on"}


def _same_or_derived_target(left: str, right: str) -> bool:
    if left == right:
        return True
    return left.startswith(f"{right}_") or right.startswith(f"{left}_")


def _safe_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
