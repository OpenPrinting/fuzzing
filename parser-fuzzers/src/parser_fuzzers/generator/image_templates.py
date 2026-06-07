from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from parser_fuzzers.output_feedback import load_output_feedback_profile
from parser_fuzzers.structure_mutator import mutate_image_structure
from parser_fuzzers.template_feedback import FeedbackSeed, load_feedback_profile
from parser_fuzzers.z3_guard import Z3_LOCK

try:
    import z3
except ImportError:  # pragma: no cover - exercised only in minimal environments
    z3 = None


IMAGE_FEEDBACK_PERIOD = 960

IMAGE_FORMATS = ("png_gray", "png_rgb", "png_rgba", "ppm", "pgm", "pbm")
IMAGE_WIDTHS = (1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 191, 192, 255)
IMAGE_HEIGHTS = (1, 2, 3, 4, 5, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64)


@dataclass(frozen=True)
class ImageTemplateInstance:
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


def image_feedback_instance(case_index: int, target_id: str = "") -> ImageTemplateInstance:
    with Z3_LOCK:
        feedback_path = os.environ.get("SMT_FUZZER_IMAGE_FEEDBACK") or os.environ.get("SMT_FUZZER_TEMPLATE_FEEDBACK", "")
        output_feedback_path = _output_feedback_path()
        target_id = target_id or _target_id()
        structure_mutator = _structure_mutator_enabled()
        expansion_level = _expansion_level()
        cycle_epoch = _cycle_epoch(case_index)
        slot = case_index % IMAGE_FEEDBACK_PERIOD
        if not feedback_path:
            return _image_feedback_instance(
                slot,
                "",
                output_feedback_path,
                target_id,
                expansion_level,
                cycle_epoch,
                structure_mutator,
            )
        return _image_feedback_instance(
            slot,
            feedback_path,
            output_feedback_path,
            target_id,
            expansion_level,
            cycle_epoch,
            structure_mutator,
        )


@lru_cache(maxsize=None)
def _image_feedback_instance(
    slot: int,
    feedback_path: str,
    output_feedback_path: str,
    target_id: str,
    expansion_level: int,
    cycle_epoch: int,
    structure_mutator: bool,
) -> ImageTemplateInstance:
    seeds = _feedback_seeds(feedback_path)
    seed_index = (slot + cycle_epoch * 37 + (slot // 17) * cycle_epoch) % len(seeds) if seeds else 0
    seed = seeds[seed_index] if seeds else None
    salted_slot = slot + cycle_epoch * 997
    effective_expansion = max(expansion_level, min(3, expansion_level + cycle_epoch))
    if structure_mutator:
        output_feedback = _loaded_output_feedback(output_feedback_path) if output_feedback_path else None
        mutated = mutate_image_structure(
            target_id=target_id,
            slot=salted_slot,
            expansion_level=effective_expansion,
            seed=seed,
            output_feedback=output_feedback,
        )
        return ImageTemplateInstance(
            image_format=mutated.image_format,
            width=mutated.width,
            height=mutated.height,
            channels=mutated.channels,
            maxval=mutated.maxval,
            payload_delta=mutated.payload_delta,
            comment_style=mutated.comment_style,
            png_interlace=mutated.png_interlace,
            objective=f"{mutated.output_format_goal}:{mutated.objective}",
            solved_by=mutated.solved_by,
        )
    return _solve_image(seed, salted_slot, effective_expansion)


def _solve_image(seed: FeedbackSeed | None, slot: int, expansion_level: int) -> ImageTemplateInstance:
    fallback = _fallback_image(seed, slot, expansion_level)
    if z3 is None:
        return fallback
    fmt = z3.Int("fmt")
    width = z3.Int("width")
    height = z3.Int("height")
    payload_delta = z3.Int("payload_delta")
    comment_style = z3.Int("comment_style")
    interlace = z3.Int("interlace")
    pixel_area = z3.Int("pixel_area")
    solver = z3.Solver()
    _domain(solver, fmt, list(range(len(IMAGE_FORMATS))))
    _domain(solver, width, list(_width_domain(seed, expansion_level)))
    _domain(solver, height, list(_height_domain(seed, expansion_level)))
    _domain(solver, payload_delta, _payload_delta_domain(expansion_level))
    _domain(solver, comment_style, [0, 1, 2, 3])
    _domain(solver, interlace, [0, 0, 0, 1])
    solver.add(pixel_area == width * height)
    if seed:
        seed_fmt = seed.fields.get("format_id")
        if seed_fmt is not None and 0 <= seed_fmt < len(IMAGE_FORMATS):
            if slot % 5 != 0:
                solver.add(fmt == seed_fmt)
        if expansion_level <= 1 and "width" in seed.fields:
            solver.add(width >= max(1, seed.fields["width"] // 2))
            solver.add(width <= max(1, seed.fields["width"] * (2 + expansion_level)))
        if expansion_level <= 1 and "height" in seed.fields:
            solver.add(height >= max(1, seed.fields["height"] // 2))
            solver.add(height <= max(1, seed.fields["height"] * (2 + expansion_level)))
    else:
        solver.add(fmt == (slot * 5 + slot // 7) % len(IMAGE_FORMATS))
    objective = _objective_name(slot, expansion_level)
    if objective == "valid":
        solver.add(payload_delta == 0, interlace == 0)
    elif objective == "short_payload":
        solver.add(payload_delta < 0, interlace == 0)
    elif objective == "extra_payload":
        solver.add(payload_delta > 0, interlace == 0)
    elif objective == "commented":
        solver.add(comment_style > 0, payload_delta == 0)
    elif objective == "png_interlace_flag":
        solver.add(fmt <= 2, interlace == 1, payload_delta == 0)
    elif objective == "edge_dimensions":
        solver.add(z3.Or(width <= 3, height <= 2, width >= 127, height >= 31), payload_delta == 0)
    elif objective == "post_scaling_valid":
        solver.add(width >= 96, height >= 16, payload_delta == 0, interlace == 0)
        solver.add(z3.Or(fmt == 1, fmt == 2, fmt == 3))
        solver.add(pixel_area >= 3072)
    elif objective == "wide_aspect_valid":
        solver.add(width >= 192, height <= 32, payload_delta == 0, interlace == 0)
    elif objective == "tall_aspect_valid":
        solver.add(width <= 64, height >= 64, payload_delta == 0, interlace == 0)
    elif objective == "maxval_sweep":
        solver.add(fmt >= 3, payload_delta == 0, interlace == 0)
    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    fmt_index = int(model.evaluate(fmt, model_completion=True).as_long())
    image_format = IMAGE_FORMATS[fmt_index]
    return ImageTemplateInstance(
        image_format=image_format,
        width=int(model.evaluate(width, model_completion=True).as_long()),
        height=int(model.evaluate(height, model_completion=True).as_long()),
        channels=_channels_for_format(image_format),
        maxval=_maxval_for_format(image_format, slot),
        payload_delta=int(model.evaluate(payload_delta, model_completion=True).as_long()),
        comment_style=int(model.evaluate(comment_style, model_completion=True).as_long()),
        png_interlace=int(model.evaluate(interlace, model_completion=True).as_long()),
        objective=objective,
        solved_by="z3-image",
    )


def _fallback_image(seed: FeedbackSeed | None, slot: int, expansion_level: int) -> ImageTemplateInstance:
    if seed and "format_id" in seed.fields:
        fmt_index = seed.fields["format_id"] % len(IMAGE_FORMATS)
        width = _select_near(IMAGE_WIDTHS, seed.fields.get("width", 8), slot)
        height = _select_near(IMAGE_HEIGHTS, seed.fields.get("height", 4), slot // 3)
    else:
        fmt_index = (slot * 5 + slot // 7) % len(IMAGE_FORMATS)
        width = IMAGE_WIDTHS[(slot * 7 + 3) % len(IMAGE_WIDTHS)]
        height = IMAGE_HEIGHTS[(slot * 5 + 1) % len(IMAGE_HEIGHTS)]
    image_format = IMAGE_FORMATS[fmt_index]
    deltas = _payload_delta_domain(expansion_level)
    objective = _objective_name(slot, expansion_level)
    exact_payload_objectives = {
        "valid",
        "commented",
        "png_interlace_flag",
        "edge_dimensions",
        "post_scaling_valid",
        "wide_aspect_valid",
        "tall_aspect_valid",
        "maxval_sweep",
    }
    payload_delta = 0 if objective in exact_payload_objectives else deltas[slot % len(deltas)]
    if objective == "short_payload" and payload_delta >= 0:
        payload_delta = -1
    if objective == "extra_payload" and payload_delta <= 0:
        payload_delta = 1
    return ImageTemplateInstance(
        image_format=image_format,
        width=width,
        height=height,
        channels=_channels_for_format(image_format),
        maxval=_maxval_for_format(image_format, slot),
        payload_delta=payload_delta,
        comment_style=slot % 4,
        png_interlace=1 if objective == "png_interlace_flag" and image_format.startswith("png") else 0,
        objective=objective,
        solved_by="fallback-image",
    )


def _feedback_seeds(path: str) -> tuple[FeedbackSeed, ...]:
    if not path:
        return ()
    profile = load_feedback_profile(path)
    return tuple(profile.images)


@lru_cache(maxsize=32)
def _loaded_output_feedback(path: str):
    return load_output_feedback_profile(path)


def _expansion_level() -> int:
    value = os.environ.get("SMT_FUZZER_IMAGE_EXPANSION_LEVEL") or os.environ.get("SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL", "0")
    try:
        return max(0, min(3, int(value)))
    except ValueError:
        return 0


def _cycle_epoch(case_index: int) -> int:
    epochs = _cycle_epochs()
    if epochs <= 1:
        return 0
    return (case_index // IMAGE_FEEDBACK_PERIOD) % epochs


def _cycle_epochs() -> int:
    value = os.environ.get("SMT_FUZZER_IMAGE_CYCLE_EPOCHS") or os.environ.get("SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS", "1")
    try:
        return max(1, min(64, int(value)))
    except ValueError:
        return 1


def _target_id() -> str:
    return (
        os.environ.get("SMT_FUZZER_TARGET_ID")
        or os.environ.get("SMT_FUZZER_IMAGE_TARGET")
        or "image_to_imagetoraster_feedback"
    )


def _output_feedback_path() -> str:
    value = os.environ.get("SMT_FUZZER_OUTPUT_FEEDBACK", "").strip()
    if not value or value == "auto":
        return ""
    return value


def _structure_mutator_enabled() -> bool:
    return os.environ.get("SMT_FUZZER_STRUCTURE_MUTATOR", "").strip().lower() in {"1", "true", "yes", "on"}


def _domain(solver, variable, values: list[int]) -> None:
    solver.add(z3.Or(*[variable == value for value in sorted(set(values))]))


def _width_domain(seed: FeedbackSeed | None, expansion_level: int) -> tuple[int, ...]:
    values = set(IMAGE_WIDTHS)
    if seed and "width" in seed.fields:
        values.update(_near_values(seed.fields["width"], 1 + expansion_level))
    if expansion_level >= 2:
        values.update({191, 192, 193, 256, 257, 511, 512})
    if expansion_level >= 3:
        values.update({767, 768, 769, 1023, 1024})
    return tuple(sorted(value for value in values if value >= 1 and value <= 1024))


def _height_domain(seed: FeedbackSeed | None, expansion_level: int) -> tuple[int, ...]:
    values = set(IMAGE_HEIGHTS)
    if seed and "height" in seed.fields:
        values.update(_near_values(seed.fields["height"], 1 + expansion_level))
    if expansion_level >= 2:
        values.update({63, 64, 65, 127, 128, 129})
    if expansion_level >= 3:
        values.update({191, 192, 193, 255, 256})
    return tuple(sorted(value for value in values if value >= 1 and value <= 256))


def _near_values(center: int, scale: int) -> set[int]:
    return {
        max(1, center - scale),
        center,
        center + scale,
        max(1, center // 2),
        max(1, center * min(4, 1 + scale)),
    }


def _payload_delta_domain(expansion_level: int) -> list[int]:
    if expansion_level <= 0:
        return [0, 0, -1, 1, 2]
    if expansion_level == 1:
        return [0, -1, 1, -2, 2, 4, 8]
    return [0, -1, 1, -2, 2, -4, 4, 8, 16, 32]


def _objective_name(slot: int, expansion_level: int) -> str:
    if _image_valid_bias_enabled():
        short_every = _short_payload_every()
        if short_every > 0 and slot % short_every == 2:
            return "short_payload"
        if expansion_level >= 2 and slot % 20 == 9:
            return "post_scaling_valid"
        if expansion_level >= 2 and slot % 24 == 11:
            return "wide_aspect_valid"
        if expansion_level >= 3 and slot % 30 == 17:
            return "tall_aspect_valid"
        if expansion_level >= 3 and slot % 28 == 13:
            return "maxval_sweep"
        if expansion_level >= 1 and slot % 18 == 5:
            return "png_interlace_flag"
        names = [
            "valid",
            "commented",
            "edge_dimensions",
            "valid",
            "extra_payload",
            "edge_dimensions",
            "post_scaling_valid" if expansion_level >= 2 else "valid",
            "valid",
            "commented",
        ]
        return names[slot % len(names)]
    names = ["valid", "commented", "short_payload", "extra_payload", "edge_dimensions"]
    if expansion_level >= 1:
        names.append("png_interlace_flag")
    if expansion_level >= 2:
        names.extend(["post_scaling_valid", "wide_aspect_valid"])
    if expansion_level >= 3:
        names.extend(["tall_aspect_valid", "maxval_sweep"])
    return names[slot % len(names)]


def _image_valid_bias_enabled() -> bool:
    return os.environ.get("SMT_FUZZER_IMAGE_VALID_BIAS", "").strip().lower() in {"1", "true", "yes", "on"}


def _short_payload_every() -> int:
    value = os.environ.get("SMT_FUZZER_IMAGE_SHORT_PAYLOAD_EVERY", "0")
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _channels_for_format(image_format: str) -> int:
    if image_format in {"png_rgb", "ppm"}:
        return 3
    if image_format == "png_rgba":
        return 4
    return 1


def _maxval_for_format(image_format: str, slot: int) -> int:
    if image_format in {"pbm"}:
        return 1
    return [1, 2, 15, 31, 127, 255, 65535][slot % 7]


def _select_near(values: tuple[int, ...], center: int, salt: int) -> int:
    choices = sorted(set(values) | _near_values(center, 2))
    return choices[salt % len(choices)]
