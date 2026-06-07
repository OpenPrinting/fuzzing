from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping

from parser_fuzzers.source_constraints import (
    active_source_constraint_key,
    choose_source_feedback_variant,
    choose_source_objective,
)
from parser_fuzzers.template_feedback import FeedbackSeed, load_feedback_profile
from parser_fuzzers.z3_guard import Z3_LOCK

try:
    import z3
except ImportError:  # pragma: no cover - exercised only in minimal environments
    z3 = None


ConstraintBuilder = Callable[[Mapping[str, Any], int], Iterable[Any]]
FallbackBuilder = Callable[[int], dict[str, int]]


CUPS_STRUCTURAL_PERIOD = 384
PWG_STRUCTURAL_PERIOD = 320
CUPS_FEEDBACK_PERIOD = 768
PWG_FEEDBACK_PERIOD = 640


@dataclass(frozen=True)
class FieldSpec:
    name: str
    values: tuple[int, ...] | None = None
    min_value: int | None = None
    max_value: int | None = None
    pin: bool = True
    salt: int = 1
    offset: int = 0
    stride: int = 11


@dataclass(frozen=True)
class TemplateObjective:
    name: str
    constraints: ConstraintBuilder


@dataclass(frozen=True)
class TemplateSpec:
    name: str
    period: int
    fields: tuple[FieldSpec, ...]
    constraints: tuple[ConstraintBuilder, ...]
    objectives: tuple[TemplateObjective, ...]
    fallback: FallbackBuilder


@dataclass(frozen=True)
class TemplateInstance:
    spec_name: str
    objective: str
    case_index: int
    fields: dict[str, int]
    solved_by: str

    def get(self, name: str) -> int:
        return self.fields[name]


def solve_template(spec: TemplateSpec, case_index: int) -> TemplateInstance:
    slot = case_index % spec.period
    objective, source_biased = choose_source_objective(spec.name, spec.objectives, slot)
    if z3 is None:
        return _fallback_instance(spec, objective, slot)

    for loosen in range(4):
        solver = z3.Solver()
        variables = {field.name: z3.Int(field.name) for field in spec.fields}
        for field in spec.fields:
            _add_field_domain(solver, variables[field.name], field)
            if field.pin and field.values and loosen == 0:
                solver.add(variables[field.name] == _selected_value(field, slot))
            elif field.pin and field.values and loosen == 1 and field.name not in {"x_res", "y_res"}:
                solver.add(variables[field.name] == _selected_value(field, slot))
            elif field.pin and field.values and loosen == 2 and field.name in {"width", "height", "bits_per_pixel"}:
                solver.add(variables[field.name] == _selected_value(field, slot))
        for builder in spec.constraints:
            solver.add(*builder(variables, slot))
        solver.add(*objective.constraints(variables, slot))
        if solver.check() == z3.sat:
            model = solver.model()
            return TemplateInstance(
                spec_name=spec.name,
                objective=objective.name,
                case_index=case_index,
                fields={
                    field.name: int(model.evaluate(variables[field.name], model_completion=True).as_long())
                    for field in spec.fields
                },
                solved_by="z3-source" if source_biased else "z3",
            )
    return _fallback_instance(spec, objective, slot)


def cups_structural_instance(case_index: int) -> TemplateInstance:
    with Z3_LOCK:
        slot = case_index % CUPS_STRUCTURAL_PERIOD
        source_key = active_source_constraint_key()
        if source_key:
            return _cups_source_structural_instance(slot, source_key)
        return _cups_structural_instance(slot)


@lru_cache(maxsize=None)
def _cups_structural_instance(slot: int) -> TemplateInstance:
    return solve_template(CUPS_RASTER_STRUCTURAL_SPEC, slot)


@lru_cache(maxsize=None)
def _cups_source_structural_instance(slot: int, source_key: str) -> TemplateInstance:
    _ = source_key
    return solve_template(CUPS_RASTER_STRUCTURAL_SPEC, slot)


def pwg_structural_instance(case_index: int) -> TemplateInstance:
    with Z3_LOCK:
        slot = case_index % PWG_STRUCTURAL_PERIOD
        source_key = active_source_constraint_key()
        if source_key:
            return _pwg_source_structural_instance(slot, source_key)
        return _pwg_structural_instance(slot)


@lru_cache(maxsize=None)
def _pwg_structural_instance(slot: int) -> TemplateInstance:
    return solve_template(PWG_RASTER_STRUCTURAL_SPEC, slot)


@lru_cache(maxsize=None)
def _pwg_source_structural_instance(slot: int, source_key: str) -> TemplateInstance:
    _ = source_key
    return solve_template(PWG_RASTER_STRUCTURAL_SPEC, slot)


def cups_feedback_instance(case_index: int) -> TemplateInstance:
    with Z3_LOCK:
        feedback_path = os.environ.get("SMT_FUZZER_TEMPLATE_FEEDBACK", "")
        if not feedback_path:
            return cups_structural_instance(case_index + CUPS_STRUCTURAL_PERIOD)
        expansion_level = _feedback_expansion_level()
        source_key = active_source_constraint_key()
        return _cups_feedback_instance(case_index % CUPS_FEEDBACK_PERIOD, feedback_path, expansion_level, source_key)


@lru_cache(maxsize=None)
def _cups_feedback_instance(slot: int, feedback_path: str, expansion_level: int, source_key: str) -> TemplateInstance:
    _ = source_key
    seeds = _feedback_seeds(feedback_path, "cups")
    if not seeds:
        return cups_structural_instance(slot + CUPS_STRUCTURAL_PERIOD)
    return _solve_cups_feedback(seeds[slot % len(seeds)], slot, expansion_level)


def pwg_feedback_instance(case_index: int) -> TemplateInstance:
    with Z3_LOCK:
        feedback_path = os.environ.get("SMT_FUZZER_TEMPLATE_FEEDBACK", "")
        if not feedback_path:
            return pwg_structural_instance(case_index + PWG_STRUCTURAL_PERIOD)
        expansion_level = _feedback_expansion_level()
        source_key = active_source_constraint_key()
        return _pwg_feedback_instance(case_index % PWG_FEEDBACK_PERIOD, feedback_path, expansion_level, source_key)


@lru_cache(maxsize=None)
def _pwg_feedback_instance(slot: int, feedback_path: str, expansion_level: int, source_key: str) -> TemplateInstance:
    _ = source_key
    seeds = _feedback_seeds(feedback_path, "pwg")
    if not seeds:
        return pwg_structural_instance(slot + PWG_STRUCTURAL_PERIOD)
    return _solve_pwg_feedback(seeds[slot % len(seeds)], slot, expansion_level)


def _add_field_domain(solver: Any, variable: Any, field: FieldSpec) -> None:
    if field.values is not None:
        solver.add(z3.Or(*[variable == value for value in sorted(set(field.values))]))
        return
    if field.min_value is not None:
        solver.add(variable >= field.min_value)
    if field.max_value is not None:
        solver.add(variable <= field.max_value)


def _selected_value(field: FieldSpec, slot: int) -> int:
    assert field.values is not None
    values = field.values
    index = (slot * field.salt + slot // max(1, field.stride) + field.offset) % len(values)
    return values[index]


def _fallback_instance(spec: TemplateSpec, objective: TemplateObjective, slot: int) -> TemplateInstance:
    return TemplateInstance(
        spec_name=spec.name,
        objective=objective.name,
        case_index=slot,
        fields=spec.fallback(slot),
        solved_by="fallback",
    )


def _ceil_div(numerator: Any, denominator: int) -> Any:
    return (numerator + denominator - 1) / denominator


def _align(value: Any, alignment: int) -> Any:
    return _ceil_div(value, alignment) * alignment


CUPS_WIDTHS = (1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 96, 127, 128, 129, 255, 511)
CUPS_HEIGHTS = (1, 2, 3, 4, 5, 8, 16)
CUPS_RESOLUTIONS = (72, 75, 100, 150, 203, 300, 360, 600, 720, 1200, 2400, 32768, 65535)
CUPS_COLOR_TUPLES = (
    (3, 1, 8),
    (18, 1, 8),
    (18, 1, 16),
    (1, 3, 24),
    (1, 3, 32),
    (6, 4, 32),
    (6, 4, 24),
)


def _cups_base_constraints(v: Mapping[str, Any], slot: int) -> Iterable[Any]:
    raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
    return [
        z3.Or(
            *[
                z3.And(v["color_space"] == color_space, v["num_colors"] == colors, v["bits_per_pixel"] == bpp)
                for color_space, colors, bpp in CUPS_COLOR_TUPLES
            ]
        ),
        v["bytes_per_line"] >= 1,
        v["bytes_per_line"] <= _align(raw_bpl, 8) + 32,
        v["row_count"] >= 1,
        v["row_count"] <= v["height"] + 2,
        v["payload_rows"] >= 1,
        v["payload_rows"] <= v["height"] + 2,
    ]


def _cups_objective(kind: str) -> ConstraintBuilder:
    def constraints(v: Mapping[str, Any], slot: int) -> Iterable[Any]:
        raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
        aligned_bpl = _align(raw_bpl, 8)
        delta = [1, 3, 7, 15][slot % 4]
        if kind == "valid_aligned":
            return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "valid_tight":
            return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "padded_line":
            return [v["bytes_per_line"] == aligned_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "short_line":
            return [raw_bpl > 1, v["bytes_per_line"] == raw_bpl - 1, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "row_count_short":
            return [v["height"] > 1, v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] - 1, v["payload_rows"] == v["height"]]
        if kind == "row_count_long":
            return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] + 1, v["payload_rows"] == v["height"]]
        if kind == "payload_short":
            return [v["height"] > 1, v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] - 1]
        if kind == "payload_extra":
            return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 1]
        raise ValueError(kind)

    return constraints


def _fallback_cups(slot: int) -> dict[str, int]:
    color_space, num_colors, bits_per_pixel = CUPS_COLOR_TUPLES[(slot * 3 + slot // 7) % len(CUPS_COLOR_TUPLES)]
    width = CUPS_WIDTHS[(slot * 7 + slot // 5) % len(CUPS_WIDTHS)]
    height = CUPS_HEIGHTS[(slot * 5 + slot // 11) % len(CUPS_HEIGHTS)]
    raw_bpl = (width * bits_per_pixel + 7) // 8
    aligned_bpl = ((raw_bpl + 7) // 8) * 8
    objective = slot % 8
    bytes_per_line = aligned_bpl
    row_count = height
    payload_rows = height
    if objective == 1:
        bytes_per_line = raw_bpl
    elif objective == 2:
        bytes_per_line = aligned_bpl + [1, 3, 7, 15][slot % 4]
    elif objective == 3 and raw_bpl > 1:
        bytes_per_line = raw_bpl - 1
    elif objective == 4 and height > 1:
        row_count = height - 1
    elif objective == 5:
        row_count = height + 1
    elif objective == 6 and height > 1:
        payload_rows = height - 1
    elif objective == 7:
        payload_rows = height + 1
    return {
        "width": width,
        "height": height,
        "compression": (0, 0, 1, 10)[slot % 4],
        "num_colors": num_colors,
        "color_space": color_space,
        "color_order": (0, 0, 1, 2)[slot % 4],
        "bits_per_pixel": bits_per_pixel,
        "pages": (1, 1, 2, 3)[slot % 4],
        "x_res": CUPS_RESOLUTIONS[(slot * 3 + 1) % len(CUPS_RESOLUTIONS)],
        "y_res": CUPS_RESOLUTIONS[(slot * 5 + 2) % len(CUPS_RESOLUTIONS)],
        "bytes_per_line": bytes_per_line,
        "row_count": row_count,
        "payload_rows": payload_rows,
    }


CUPS_RASTER_STRUCTURAL_SPEC = TemplateSpec(
    name="cups_raster_structural",
    period=CUPS_STRUCTURAL_PERIOD,
    fields=(
        FieldSpec("width", values=CUPS_WIDTHS, salt=7, stride=5),
        FieldSpec("height", values=CUPS_HEIGHTS, salt=5, stride=11),
        FieldSpec("compression", values=(0, 0, 1, 10), salt=3),
        FieldSpec("num_colors", values=(1, 3, 4), pin=False),
        FieldSpec("color_space", values=(1, 3, 6, 18), pin=False),
        FieldSpec("color_order", values=(0, 0, 1, 2), salt=5),
        FieldSpec("bits_per_pixel", values=(8, 16, 24, 32), pin=False),
        FieldSpec("pages", values=(1, 1, 2, 3), salt=11),
        FieldSpec("x_res", values=CUPS_RESOLUTIONS, salt=3, offset=1),
        FieldSpec("y_res", values=CUPS_RESOLUTIONS, salt=5, offset=2),
        FieldSpec("bytes_per_line", min_value=1, max_value=4096, pin=False),
        FieldSpec("row_count", min_value=1, max_value=64, pin=False),
        FieldSpec("payload_rows", min_value=1, max_value=64, pin=False),
    ),
    constraints=(_cups_base_constraints,),
    objectives=tuple(
        TemplateObjective(name, _cups_objective(name))
        for name in (
            "valid_aligned",
            "valid_tight",
            "padded_line",
            "short_line",
            "row_count_short",
            "row_count_long",
            "payload_short",
            "payload_extra",
        )
    ),
    fallback=_fallback_cups,
)


PWG_WIDTHS = (1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255, 511)
PWG_HEIGHTS = (1, 2, 3, 4, 8, 16)
PWG_BPP = (1, 8, 16, 24, 32)
PWG_RESOLUTIONS = (72, 150, 203, 300, 360, 600, 720, 1200, 2400, 32768, 65535, 65536, 2147483647)


def _pwg_base_constraints(v: Mapping[str, Any], slot: int) -> Iterable[Any]:
    raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
    return [
        v["bytes_per_line"] >= 1,
        v["bytes_per_line"] <= raw_bpl + 64,
        v["row_count"] >= 1,
        v["row_count"] <= v["height"] + 2,
        v["payload_rows"] >= 1,
        v["payload_rows"] <= v["height"] + 2,
    ]


def _pwg_objective(kind: str) -> ConstraintBuilder:
    def constraints(v: Mapping[str, Any], slot: int) -> Iterable[Any]:
        raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
        delta = [1, 2, 4, 8, 16][slot % 5]
        if kind == "valid_exact":
            return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "padded_line":
            return [v["bytes_per_line"] == raw_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "short_line":
            return [raw_bpl > 1, v["bytes_per_line"] == raw_bpl - 1, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
        if kind == "row_count_short":
            return [v["height"] > 1, v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"] - 1, v["payload_rows"] == v["height"]]
        if kind == "row_count_long":
            return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"] + 1, v["payload_rows"] == v["height"]]
        if kind == "payload_short":
            return [v["height"] > 1, v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] - 1]
        if kind == "payload_extra":
            return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 1]
        raise ValueError(kind)

    return constraints


def _fallback_pwg(slot: int) -> dict[str, int]:
    width = PWG_WIDTHS[(slot * 5 + slot // 3) % len(PWG_WIDTHS)]
    height = PWG_HEIGHTS[(slot * 7 + slot // 13) % len(PWG_HEIGHTS)]
    bits_per_pixel = PWG_BPP[(slot * 3 + slot // 17) % len(PWG_BPP)]
    raw_bpl = max(1, (width * bits_per_pixel + 7) // 8)
    objective = slot % 7
    bytes_per_line = raw_bpl
    row_count = height
    payload_rows = height
    if objective == 1:
        bytes_per_line = raw_bpl + [1, 2, 4, 8, 16][slot % 5]
    elif objective == 2 and raw_bpl > 1:
        bytes_per_line = raw_bpl - 1
    elif objective == 3 and height > 1:
        row_count = height - 1
    elif objective == 4:
        row_count = height + 1
    elif objective == 5 and height > 1:
        payload_rows = height - 1
    elif objective == 6:
        payload_rows = height + 1
    return {
        "width": width,
        "height": height,
        "bits_per_pixel": bits_per_pixel,
        "x_res": PWG_RESOLUTIONS[(slot * 2 + 3) % len(PWG_RESOLUTIONS)],
        "y_res": PWG_RESOLUTIONS[(slot * 5 + 1) % len(PWG_RESOLUTIONS)],
        "pages": (1, 1, 2, 3)[slot % 4],
        "bytes_per_line": bytes_per_line,
        "row_count": row_count,
        "payload_rows": payload_rows,
    }


PWG_RASTER_STRUCTURAL_SPEC = TemplateSpec(
    name="pwg_raster_structural",
    period=PWG_STRUCTURAL_PERIOD,
    fields=(
        FieldSpec("width", values=PWG_WIDTHS, salt=5, stride=3),
        FieldSpec("height", values=PWG_HEIGHTS, salt=7, stride=13),
        FieldSpec("bits_per_pixel", values=PWG_BPP, salt=3, stride=17),
        FieldSpec("x_res", values=PWG_RESOLUTIONS, salt=2, offset=3),
        FieldSpec("y_res", values=PWG_RESOLUTIONS, salt=5, offset=1),
        FieldSpec("pages", values=(1, 1, 2, 3), salt=11),
        FieldSpec("bytes_per_line", min_value=1, max_value=4096, pin=False),
        FieldSpec("row_count", min_value=1, max_value=64, pin=False),
        FieldSpec("payload_rows", min_value=1, max_value=64, pin=False),
    ),
    constraints=(_pwg_base_constraints,),
    objectives=tuple(
        TemplateObjective(name, _pwg_objective(name))
        for name in (
            "valid_exact",
            "padded_line",
            "short_line",
            "row_count_short",
            "row_count_long",
            "payload_short",
            "payload_extra",
        )
    ),
    fallback=_fallback_pwg,
)


@lru_cache(maxsize=None)
def _loaded_feedback(path: str):
    return load_feedback_profile(path)


def _feedback_seeds(path: str, kind: str) -> tuple[FeedbackSeed, ...]:
    profile = _loaded_feedback(path)
    seeds = profile.cups if kind == "cups" else profile.pwg
    return tuple(seeds)


def _solve_cups_feedback(seed: FeedbackSeed, slot: int, expansion_level: int = 0) -> TemplateInstance:
    seed = _sanitize_feedback_seed(seed, CUPS_RASTER_STRUCTURAL_SPEC)
    variant, source_biased = choose_source_feedback_variant(
        "cups",
        _cups_feedback_variant_count(expansion_level),
        slot,
    )
    if z3 is None:
        return _feedback_fallback("cups_raster_feedback", seed, slot, _cups_feedback_fields(seed, slot, variant))

    for loosen in range(_feedback_loosen_limit(expansion_level)):
        solver = z3.Solver()
        variables = {field.name: z3.Int(field.name) for field in CUPS_RASTER_STRUCTURAL_SPEC.fields}
        for field in CUPS_RASTER_STRUCTURAL_SPEC.fields:
            _add_field_domain(solver, variables[field.name], field)
        solver.add(*_cups_base_constraints(variables, slot))
        solver.add(
            *_feedback_neighborhood_constraints(
                variables,
                seed,
                CUPS_RASTER_STRUCTURAL_SPEC,
                loosen,
                cups=True,
                expansion_level=expansion_level,
            )
        )
        solver.add(*_cups_feedback_objective(variables, seed, slot, variant))
        if solver.check() == z3.sat:
            model = solver.model()
            return TemplateInstance(
                spec_name="cups_raster_feedback",
                objective=f"feedback:{_feedback_variant_name(variant)}:{seed.source}",
                case_index=slot,
                fields={
                    field.name: int(model.evaluate(variables[field.name], model_completion=True).as_long())
                    for field in CUPS_RASTER_STRUCTURAL_SPEC.fields
                },
                solved_by="z3-feedback-source" if source_biased else "z3-feedback",
            )
    return _feedback_fallback("cups_raster_feedback", seed, slot, _cups_feedback_fields(seed, slot, variant))


def _solve_pwg_feedback(seed: FeedbackSeed, slot: int, expansion_level: int = 0) -> TemplateInstance:
    seed = _sanitize_feedback_seed(seed, PWG_RASTER_STRUCTURAL_SPEC)
    variant, source_biased = choose_source_feedback_variant(
        "pwg",
        _pwg_feedback_variant_count(expansion_level),
        slot,
    )
    if z3 is None:
        return _feedback_fallback("pwg_raster_feedback", seed, slot, _pwg_feedback_fields(seed, slot, variant))

    for loosen in range(_feedback_loosen_limit(expansion_level)):
        solver = z3.Solver()
        variables = {field.name: z3.Int(field.name) for field in PWG_RASTER_STRUCTURAL_SPEC.fields}
        for field in PWG_RASTER_STRUCTURAL_SPEC.fields:
            _add_field_domain(solver, variables[field.name], field)
        solver.add(*_pwg_base_constraints(variables, slot))
        solver.add(
            *_feedback_neighborhood_constraints(
                variables,
                seed,
                PWG_RASTER_STRUCTURAL_SPEC,
                loosen,
                cups=False,
                expansion_level=expansion_level,
            )
        )
        solver.add(*_pwg_feedback_objective(variables, seed, slot, variant))
        if solver.check() == z3.sat:
            model = solver.model()
            return TemplateInstance(
                spec_name="pwg_raster_feedback",
                objective=f"feedback:{_feedback_variant_name(variant)}:{seed.source}",
                case_index=slot,
                fields={
                    field.name: int(model.evaluate(variables[field.name], model_completion=True).as_long())
                    for field in PWG_RASTER_STRUCTURAL_SPEC.fields
                },
                solved_by="z3-feedback-source" if source_biased else "z3-feedback",
            )
    return _feedback_fallback("pwg_raster_feedback", seed, slot, _pwg_feedback_fields(seed, slot, variant))


def _feedback_neighborhood_constraints(
    variables: Mapping[str, Any],
    seed: FeedbackSeed,
    spec: TemplateSpec,
    loosen: int,
    *,
    cups: bool,
    expansion_level: int = 0,
) -> list[Any]:
    fields = seed.fields
    constraints: list[Any] = []
    radius_scale = 1 + max(0, expansion_level)
    for field in spec.fields:
        if field.name not in fields or field.values is None:
            continue
        value = fields[field.name]
        if loosen == 0 and field.name in {"width", "height", "bits_per_pixel", "color_space", "num_colors"}:
            if value in field.values:
                constraints.append(variables[field.name] == value)
            continue
        if loosen <= 1 and field.name in {"width", "height", "bits_per_pixel"}:
            allowed = _near_values(field.values, value, _feedback_radius(field.name, value) * radius_scale)
            if allowed:
                constraints.append(z3.Or(*[variables[field.name] == item for item in allowed]))
        elif loosen <= 1 and cups and field.name in {"color_space", "num_colors"} and value in field.values:
            constraints.append(variables[field.name] == value)
        elif loosen <= 1 and field.name in {"x_res", "y_res"}:
            allowed = _near_values(field.values, value, max(1, (value // 2) * radius_scale))
            if allowed:
                constraints.append(z3.Or(*[variables[field.name] == item for item in allowed]))
    return constraints


def _cups_feedback_objective(v: Mapping[str, Any], seed: FeedbackSeed, slot: int, variant: int) -> list[Any]:
    raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
    aligned_bpl = _align(raw_bpl, 8)
    seed_bpl = max(1, seed.fields.get("bytes_per_line", 1))
    delta = [1, 2, 4, 8][slot % 4]
    if variant == 0:
        return [v["bytes_per_line"] == seed_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 1:
        return [raw_bpl > delta, v["bytes_per_line"] == raw_bpl - delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 2:
        return [v["bytes_per_line"] == raw_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 3:
        return [v["bytes_per_line"] == _seed_delta(seed_bpl, -delta), v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 4:
        return [v["bytes_per_line"] == seed_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 5:
        return [v["height"] > 1, v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] - 1, v["payload_rows"] == v["height"]]
    if variant == 6:
        return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] + 1, v["payload_rows"] == v["height"]]
    if variant == 7:
        return [v["height"] > 1, v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] - 1]
    if variant == 8:
        return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 1]
    if variant == 9:
        return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 10:
        return [v["bytes_per_line"] == aligned_bpl + 16, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 11:
        return [v["bytes_per_line"] == aligned_bpl + 32, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 12:
        return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] + 2, v["payload_rows"] == v["height"]]
    if variant == 13:
        return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 2]
    return [v["bytes_per_line"] == aligned_bpl, v["row_count"] == v["height"] + 2, v["payload_rows"] == v["height"] + 2]


def _pwg_feedback_objective(v: Mapping[str, Any], seed: FeedbackSeed, slot: int, variant: int) -> list[Any]:
    raw_bpl = _ceil_div(v["width"] * v["bits_per_pixel"], 8)
    seed_bpl = max(1, seed.fields.get("bytes_per_line", 1))
    delta = [1, 2, 4, 8][slot % 4]
    if variant == 0:
        return [v["bytes_per_line"] == seed_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 1:
        return [raw_bpl > delta, v["bytes_per_line"] == raw_bpl - delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 2:
        return [v["bytes_per_line"] == raw_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 3:
        return [v["bytes_per_line"] == _seed_delta(seed_bpl, -delta), v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 4:
        return [v["bytes_per_line"] == seed_bpl + delta, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 5:
        return [v["height"] > 1, v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"] - 1, v["payload_rows"] == v["height"]]
    if variant == 6:
        return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"] + 1, v["payload_rows"] == v["height"]]
    if variant == 7:
        return [v["height"] > 1, v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] - 1]
    if variant == 8:
        return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 1]
    if variant == 9:
        return [v["bytes_per_line"] == raw_bpl + 16, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 10:
        return [v["bytes_per_line"] == raw_bpl + 32, v["row_count"] == v["height"], v["payload_rows"] == v["height"]]
    if variant == 11:
        return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"] + 2, v["payload_rows"] == v["height"]]
    return [v["bytes_per_line"] == raw_bpl, v["row_count"] == v["height"], v["payload_rows"] == v["height"] + 2]


def _cups_feedback_fields(seed: FeedbackSeed, slot: int, variant: int) -> dict[str, int]:
    fields = dict(_fallback_cups(slot))
    fields.update({key: value for key, value in seed.fields.items() if key in fields})
    return _apply_feedback_fallback_variant(fields, slot, variant, cups=True)


def _pwg_feedback_fields(seed: FeedbackSeed, slot: int, variant: int) -> dict[str, int]:
    fields = dict(_fallback_pwg(slot))
    fields.update({key: value for key, value in seed.fields.items() if key in fields})
    return _apply_feedback_fallback_variant(fields, slot, variant, cups=False)


def _sanitize_feedback_seed(seed: FeedbackSeed, spec: TemplateSpec) -> FeedbackSeed:
    sanitized = dict(seed.fields)
    for field in spec.fields:
        if field.name not in sanitized:
            continue
        sanitized[field.name] = _sanitize_feedback_value(field, sanitized[field.name])
    return FeedbackSeed(
        kind=seed.kind,
        source=seed.source,
        target_id=seed.target_id,
        case_id=seed.case_id,
        document_path=seed.document_path,
        crashed=seed.crashed,
        timed_out=seed.timed_out,
        fields=sanitized,
    )


def _sanitize_feedback_value(field: FieldSpec, value: int) -> int:
    if field.values is not None:
        return min(sorted(set(field.values)), key=lambda item: (abs(item - value), item))
    if field.min_value is not None:
        value = max(field.min_value, value)
    if field.max_value is not None:
        value = min(field.max_value, value)
    return value


def _apply_feedback_fallback_variant(fields: dict[str, int], slot: int, variant: int, *, cups: bool) -> dict[str, int]:
    raw_bpl = max(1, (fields["width"] * fields["bits_per_pixel"] + 7) // 8)
    aligned_bpl = ((raw_bpl + 7) // 8) * 8 if cups else raw_bpl
    seed_bpl = max(1, fields.get("bytes_per_line", raw_bpl))
    delta = [1, 2, 4, 8][slot % 4]
    if variant == 1:
        fields["bytes_per_line"] = max(1, raw_bpl - delta)
    elif variant == 2:
        fields["bytes_per_line"] = raw_bpl + delta
    elif variant == 3:
        fields["bytes_per_line"] = max(1, seed_bpl - delta)
    elif variant == 4:
        fields["bytes_per_line"] = seed_bpl + delta
    elif variant == 5:
        fields["bytes_per_line"] = aligned_bpl
        fields["row_count"] = max(1, fields["height"] - 1)
    elif variant == 6:
        fields["bytes_per_line"] = aligned_bpl
        fields["row_count"] = fields["height"] + 1
    elif variant == 7:
        fields["bytes_per_line"] = aligned_bpl
        fields["payload_rows"] = max(1, fields["height"] - 1)
    elif variant == 8:
        fields["bytes_per_line"] = aligned_bpl
        fields["payload_rows"] = fields["height"] + 1
    elif variant == 9 and not cups:
        fields["bytes_per_line"] = raw_bpl + 16
    elif variant == 10:
        fields["bytes_per_line"] = aligned_bpl + 16 if cups else raw_bpl + 32
    elif variant == 11:
        if cups:
            fields["bytes_per_line"] = aligned_bpl + 32
        else:
            fields["bytes_per_line"] = raw_bpl
            fields["row_count"] = fields["height"] + 2
    elif variant == 12:
        fields["bytes_per_line"] = aligned_bpl
        if cups:
            fields["row_count"] = fields["height"] + 2
        else:
            fields["payload_rows"] = fields["height"] + 2
    elif variant == 13:
        fields["bytes_per_line"] = aligned_bpl
        fields["payload_rows"] = fields["height"] + 2
    elif variant >= 14:
        fields["bytes_per_line"] = aligned_bpl
        fields["row_count"] = fields["height"] + 2
        fields["payload_rows"] = fields["height"] + 2
    else:
        fields["bytes_per_line"] = seed_bpl if variant == 0 else raw_bpl
    fields.setdefault("row_count", fields["height"])
    fields.setdefault("payload_rows", fields["height"])
    return fields


def _feedback_fallback(spec_name: str, seed: FeedbackSeed, slot: int, fields: dict[str, int]) -> TemplateInstance:
    return TemplateInstance(
        spec_name=spec_name,
        objective=f"feedback:{_feedback_variant_name(slot)}:{seed.source}",
        case_index=slot,
        fields=fields,
        solved_by="fallback-feedback",
    )


def _near_values(values: tuple[int, ...], center: int, radius: int) -> list[int]:
    allowed = [value for value in sorted(set(values)) if abs(value - center) <= radius]
    return allowed or ([center] if center in values else [])


def _feedback_radius(name: str, value: int) -> int:
    if name == "width":
        return max(2, value // 4)
    if name == "height":
        return 2
    return max(1, value // 2)


def _seed_delta(value: int, delta: int) -> int:
    return max(1, value + delta)


def _feedback_variant_name(variant: int) -> str:
    names = (
        "seed_line",
        "raw_minus",
        "raw_plus",
        "seed_minus",
        "seed_plus",
        "row_short",
        "row_long",
        "payload_short",
        "payload_extra",
        "valid_tight",
        "wide_pad_16",
        "wide_pad_32",
        "row_plus_two",
        "payload_plus_two",
        "row_payload_plus_two",
    )
    return names[variant % len(names)]


def _feedback_expansion_level() -> int:
    value = os.environ.get("SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL", "0")
    try:
        return max(0, min(3, int(value)))
    except ValueError:
        return 0


def _feedback_loosen_limit(expansion_level: int) -> int:
    return max(3, min(6, 3 + expansion_level))


def _cups_feedback_variant_count(expansion_level: int) -> int:
    return 10 if expansion_level <= 0 else min(15, 10 + (2 * expansion_level))


def _pwg_feedback_variant_count(expansion_level: int) -> int:
    return 8 if expansion_level <= 0 else min(13, 8 + (2 * expansion_level))
