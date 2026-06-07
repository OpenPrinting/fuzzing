from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

from parser_fuzzers.format_specs import ImageGoal


PNM_FORMATS = frozenset({"ppm", "pgm", "pbm"})
PNM_MAXVAL_FORMATS = frozenset({"ppm", "pgm"})
PNG_FORMATS = frozenset({"png_gray", "png_rgb", "png_rgba"})


def expand_image_goals(
    *,
    target_id: str,
    goals: tuple[ImageGoal, ...],
    profile: Any | None = None,
    slot: int = 0,
) -> tuple[ImageGoal, ...]:
    if not goals or not _enabled():
        return goals
    budget = _budget()
    if budget <= 0:
        return goals

    ordered = sorted(
        goals,
        key=lambda goal: (
            _objective_count(profile, target_id, goal.name),
            _stable_int(f"{target_id}|{goal.name}|{slot}"),
            goal.name,
        ),
    )

    generated: list[ImageGoal] = []
    seen = {goal.name for goal in goals}
    for base in ordered:
        for variant in _variants(base):
            if variant.name in seen:
                continue
            generated.append(variant)
            seen.add(variant.name)
            if len(generated) >= budget:
                break
        if len(generated) >= budget:
            break

    if not generated:
        return goals
    shift = slot % len(generated)
    rotated = generated[shift:] + generated[:shift]
    return goals + tuple(rotated)


def _variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    variants: list[ImageGoal] = []
    variants.extend(_payload_variants(base))
    variants.extend(_pnm_comment_variants(base))
    variants.extend(_maxval_variants(base))
    variants.extend(_png_variants(base))
    variants.extend(_dimension_variants(base))
    return tuple(variants)


def _payload_variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    return (
        _named_replace(base, "short-payload", payload_policy="short"),
        _named_replace(base, "extra-payload", payload_policy="extra"),
    )


def _pnm_comment_variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    pnm_formats = _allowed_subset(base, PNM_FORMATS)
    if not pnm_formats:
        return ()
    return (
        _named_replace(base, "inline-comment", allowed_formats=pnm_formats, comment_style=3),
        _named_replace(base, "crlf-tabs", allowed_formats=pnm_formats, comment_style=2),
    )


def _maxval_variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    maxval_formats = _allowed_subset(base, PNM_MAXVAL_FORMATS)
    if not maxval_formats:
        return ()
    return (
        _named_replace(base, "wide-maxval", allowed_formats=maxval_formats, maxval_class="wide"),
        _named_replace(base, "low-maxval", allowed_formats=maxval_formats, maxval_class="low"),
    )


def _png_variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    png_formats = _allowed_subset(base, PNG_FORMATS)
    if not png_formats:
        return ()
    return (
        _named_replace(base, "interlaced", allowed_formats=png_formats, png_interlace=1),
    )


def _dimension_variants(base: ImageGoal) -> tuple[ImageGoal, ...]:
    variants: list[ImageGoal] = []
    large_width = max(base.min_width, 256)
    large_height = max(base.min_height, 64)
    large_area = max(base.min_area, 32768)
    if _dimension_goal_is_feasible(
        min_width=large_width,
        min_height=large_height,
        min_area=large_area,
        max_width=max(base.max_width, large_width),
        max_height=max(base.max_height, large_height),
        aspect=base.aspect,
    ):
        variants.append(
            _named_replace(
                base,
                "large-area",
                min_width=large_width,
                min_height=large_height,
                min_area=large_area,
                max_width=max(base.max_width, large_width),
                max_height=max(base.max_height, large_height),
            )
        )

    edge_width = max(base.min_width, 31)
    edge_height = max(base.min_height, 31)
    edge_max_width = max(edge_width, min(base.max_width, 129))
    edge_max_height = max(edge_height, min(base.max_height, 129))
    edge_area = max(base.min_area, min(edge_max_width * edge_max_height, 4096))
    if _dimension_goal_is_feasible(
        min_width=edge_width,
        min_height=edge_height,
        min_area=edge_area,
        max_width=edge_max_width,
        max_height=edge_max_height,
        aspect="any",
    ):
        variants.append(
            _named_replace(
                base,
                "edge-window",
                min_width=edge_width,
                min_height=edge_height,
                min_area=edge_area,
                max_width=edge_max_width,
                max_height=edge_max_height,
                aspect="any",
            )
        )
    return tuple(variants)


def _dimension_goal_is_feasible(
    *,
    min_width: int,
    min_height: int,
    min_area: int,
    max_width: int,
    max_height: int,
    aspect: str,
) -> bool:
    if min_width > max_width or min_height > max_height:
        return False
    if max_width * max_height < min_area:
        return False
    if aspect == "wide" and max_width < min_height * 4:
        return False
    if aspect == "tall" and max_height < min_width * 3:
        return False
    return True


def _named_replace(base: ImageGoal, suffix: str, **changes: Any) -> ImageGoal:
    return replace(base, name=f"auto-{base.name}-{suffix}", **changes)


def _allowed_subset(base: ImageGoal, allowed: frozenset[str]) -> tuple[str, ...]:
    return tuple(item for item in base.allowed_formats if item in allowed)


def _objective_count(profile: Any | None, target_id: str, objective: str) -> int:
    if profile is None:
        return 0
    counts = getattr(profile, "objective_counts", {})
    try:
        return int(counts.get(f"{target_id}|{objective}", 0))
    except (AttributeError, TypeError, ValueError):
        return 0


def _enabled() -> bool:
    return os.environ.get("SMT_FUZZER_AUTO_DIMENSIONS", "").strip().lower() in {"1", "true", "yes", "on"}


def _budget() -> int:
    value = os.environ.get("SMT_FUZZER_AUTO_DIMENSION_BUDGET", "64")
    try:
        return max(0, min(512, int(value)))
    except ValueError:
        return 64


def _stable_int(value: str) -> int:
    total = 0
    for char in value:
        total = (total * 131 + ord(char)) & 0xFFFFFFFF
    return total
