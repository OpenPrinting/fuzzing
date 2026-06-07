from __future__ import annotations

from dataclasses import dataclass

from parser_fuzzers.crash_avoidance import (
    CrashAvoidanceProfile,
    generalized_crash_avoidance_enabled,
    preferred_crash_avoidance_profile,
)
from parser_fuzzers.format_specs import IMAGE_FORMATS, ImageGoal, image_channels, image_format_id, maxval_for_class
from parser_fuzzers.template_feedback import FeedbackSeed

try:
    import z3
except ImportError:  # pragma: no cover - depends on optional test environment
    z3 = None


@dataclass(frozen=True)
class ImageRepairResult:
    image_format: str
    width: int
    height: int
    channels: int
    maxval: int
    payload_delta: int
    comment_style: int
    png_interlace: int
    objective: str
    solved_by: str


def repair_image_goal(
    *,
    goal: ImageGoal,
    slot: int,
    expansion_level: int,
    seed: FeedbackSeed | None = None,
    target_id: str = "",
) -> ImageRepairResult:
    avoidance = preferred_crash_avoidance_profile()
    fallback = _fallback(goal, slot, seed, target_id=target_id, avoidance=avoidance)
    if z3 is None:
        return fallback

    fmt = z3.Int("fmt")
    width = z3.Int("width")
    height = z3.Int("height")
    payload_delta = z3.Int("payload_delta")
    comment_style = z3.Int("comment_style")
    interlace = z3.Int("interlace")
    area = z3.Int("area")

    solver = z3.Solver()
    _domain(solver, fmt, [image_format_id(item) for item in goal.allowed_formats])
    _domain(solver, width, _dimension_domain(goal.min_width, goal.max_width, slot, expansion_level))
    _domain(solver, height, _dimension_domain(goal.min_height, goal.max_height, slot // 3, expansion_level))
    _domain(solver, payload_delta, _payload_domain(goal.payload_policy, expansion_level))
    _domain(solver, comment_style, [goal.comment_style] if goal.comment_style is not None else [0, 1, 2, 3])
    _domain(solver, interlace, [goal.png_interlace])
    solver.add(area == width * height)
    solver.add(width >= goal.min_width, width <= goal.max_width)
    solver.add(height >= goal.min_height, height <= goal.max_height)
    solver.add(area >= goal.min_area)
    if goal.aspect == "wide":
        solver.add(width >= height * 4)
    elif goal.aspect == "tall":
        solver.add(height >= width * 3)
    if goal.payload_policy == "exact":
        solver.add(payload_delta == 0)
    elif goal.payload_policy == "short":
        solver.add(payload_delta < 0)
    elif goal.payload_policy == "extra":
        solver.add(payload_delta > 0)
    avoided = _add_crash_avoidance_constraints(
        solver=solver,
        target_id=target_id,
        goal=goal,
        fmt=fmt,
        payload_delta=payload_delta,
        interlace=interlace,
        avoidance=avoidance,
    )
    if seed and expansion_level <= 1:
        if "width" in seed.fields:
            solver.add(width >= max(1, seed.fields["width"] // 2))
            solver.add(width <= max(1, seed.fields["width"] * 3))
        if "height" in seed.fields:
            solver.add(height >= max(1, seed.fields["height"] // 2))
            solver.add(height <= max(1, seed.fields["height"] * 3))

    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    image_format = IMAGE_FORMATS[int(model.evaluate(fmt, model_completion=True).as_long())]
    return ImageRepairResult(
        image_format=image_format,
        width=int(model.evaluate(width, model_completion=True).as_long()),
        height=int(model.evaluate(height, model_completion=True).as_long()),
        channels=image_channels(image_format),
        maxval=maxval_for_class(image_format, goal.maxval_class, slot),
        payload_delta=int(model.evaluate(payload_delta, model_completion=True).as_long()),
        comment_style=int(model.evaluate(comment_style, model_completion=True).as_long()),
        png_interlace=int(model.evaluate(interlace, model_completion=True).as_long()),
        objective=goal.name,
        solved_by="z3-structure-avoid" if avoided else "z3-structure",
    )


def _fallback(
    goal: ImageGoal,
    slot: int,
    seed: FeedbackSeed | None,
    *,
    target_id: str = "",
    avoidance: CrashAvoidanceProfile | None = None,
) -> ImageRepairResult:
    if seed and "format_id" in seed.fields:
        allowed = tuple(item for item in goal.allowed_formats if image_format_id(item) == seed.fields["format_id"])
        image_format = allowed[0] if allowed else goal.allowed_formats[slot % len(goal.allowed_formats)]
    else:
        image_format = goal.allowed_formats[slot % len(goal.allowed_formats)]
    width = max(goal.min_width, _fallback_dimension(goal.min_width, goal.max_width, slot))
    height = max(goal.min_height, _fallback_dimension(goal.min_height, goal.max_height, slot // 3))
    if goal.aspect == "wide":
        width = max(width, height * 4)
    elif goal.aspect == "tall":
        height = max(height, width * 3)
    payload_delta = 0
    if goal.payload_policy == "short":
        payload_delta = -1
    elif goal.payload_policy == "extra":
        payload_delta = 1
    image_format, payload_delta = _avoid_fallback_exact_hazard(
        goal=goal,
        target_id=target_id,
        image_format=image_format,
        payload_delta=payload_delta,
        interlace=goal.png_interlace,
        avoidance=avoidance,
    )
    return ImageRepairResult(
        image_format=image_format,
        width=min(width, goal.max_width),
        height=min(height, goal.max_height),
        channels=image_channels(image_format),
        maxval=maxval_for_class(image_format, goal.maxval_class, slot),
        payload_delta=payload_delta,
        comment_style=goal.comment_style if goal.comment_style is not None else slot % 4,
        png_interlace=goal.png_interlace,
        objective=goal.name,
        solved_by="fallback-structure",
    )


def _add_crash_avoidance_constraints(
    *,
    solver,
    target_id: str,
    goal: ImageGoal,
    fmt,
    payload_delta,
    interlace,
    avoidance: CrashAvoidanceProfile,
) -> bool:
    if not target_id or not avoidance.hazards:
        return False
    added = False
    exact_hazards = avoidance.hazards_for_goal(target_id, goal)
    hazards = list(exact_hazards)
    if generalized_crash_avoidance_enabled():
        seen = {hazard.raw for hazard in hazards}
        for hazard in avoidance.generalized_hazards_for_goal(target_id, goal):
            if hazard.raw in seen:
                continue
            hazards.append(hazard)
            seen.add(hazard.raw)
    for hazard in hazards:
        clauses = []
        fmt_id = image_format_id(hazard.image_format)
        if hazard.image_format in goal.allowed_formats:
            clauses.append(fmt != fmt_id)
        payload_clause = _payload_difference_clause(payload_delta, hazard.payload)
        if payload_clause is not None:
            clauses.append(payload_clause)
        if hazard.interlace is not None:
            clauses.append(interlace != hazard.interlace)
        if clauses:
            solver.add(z3.Or(*clauses))
            added = True
    return added


def _payload_difference_clause(payload_delta, payload: str):
    if payload == "short":
        return payload_delta >= 0
    if payload == "extra":
        return payload_delta <= 0
    if payload == "exact":
        return payload_delta != 0
    return None


def _avoid_fallback_exact_hazard(
    *,
    goal: ImageGoal,
    target_id: str,
    image_format: str,
    payload_delta: int,
    interlace: int,
    avoidance: CrashAvoidanceProfile | None,
) -> tuple[str, int]:
    if not target_id or avoidance is None or not avoidance.hazards:
        return image_format, payload_delta
    payload = _payload_label(payload_delta)
    objective = f"{goal.output_format}:{goal.name}"
    blocked = avoidance.blocks_exact(
        target_id=target_id,
        objective=objective,
        image_format=image_format,
        payload=payload,
        interlace=interlace,
    )
    if generalized_crash_avoidance_enabled():
        blocked = blocked or avoidance.blocks_generalized(
            target_id=target_id,
            image_format=image_format,
            payload=payload,
            interlace=interlace,
        )
    if not blocked:
        return image_format, payload_delta
    for candidate in goal.allowed_formats:
        candidate_blocked = avoidance.blocks_exact(
            target_id=target_id,
            objective=objective,
            image_format=candidate,
            payload=payload,
            interlace=interlace,
        )
        if generalized_crash_avoidance_enabled():
            candidate_blocked = candidate_blocked or avoidance.blocks_generalized(
                target_id=target_id,
                image_format=candidate,
                payload=payload,
                interlace=interlace,
            )
        if not candidate_blocked:
            return candidate, payload_delta
    return image_format, payload_delta


def _payload_label(payload_delta: int) -> str:
    if payload_delta < 0:
        return "short"
    if payload_delta > 0:
        return "extra"
    return "exact"


def _dimension_domain(min_value: int, max_value: int, salt: int, expansion_level: int) -> list[int]:
    values = {
        min_value,
        min(max_value, min_value + 1),
        min(max_value, min_value * 2),
        min(max_value, min_value * 4),
        31,
        32,
        63,
        64,
        95,
        96,
        127,
        128,
        191,
        192,
        255,
        256,
    }
    if expansion_level >= 2:
        values.update({511, 512})
    if expansion_level >= 3:
        values.update({767, 768, 1023, 1024})
    ordered = sorted(value for value in values if min_value <= value <= max_value)
    if not ordered:
        return [min_value]
    return ordered[salt % len(ordered):] + ordered[: salt % len(ordered)]


def _fallback_dimension(min_value: int, max_value: int, salt: int) -> int:
    values = _dimension_domain(min_value, max_value, salt, 3)
    return values[0]


def _payload_domain(policy: str, expansion_level: int) -> list[int]:
    if policy == "short":
        return [-1, -2, -4, -8]
    if policy == "extra":
        return [1, 2, 4, 8, 16, 32]
    if expansion_level >= 2:
        return [0, 0, 0, 1, -1]
    return [0]


def _domain(solver, variable, values: list[int]) -> None:
    solver.add(z3.Or(*[variable == value for value in sorted(set(values))]))
