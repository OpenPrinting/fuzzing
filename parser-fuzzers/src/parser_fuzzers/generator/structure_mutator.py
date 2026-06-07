from __future__ import annotations

from dataclasses import dataclass

from parser_fuzzers.constraint_repair import ImageRepairResult, repair_image_goal
from parser_fuzzers.output_feedback import OutputFeedbackProfile, choose_image_goal
from parser_fuzzers.template_feedback import FeedbackSeed


@dataclass(frozen=True)
class MutatedImageStructure:
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
    output_format_goal: str


def mutate_image_structure(
    *,
    target_id: str,
    slot: int,
    expansion_level: int,
    seed: FeedbackSeed | None = None,
    output_feedback: OutputFeedbackProfile | None = None,
) -> MutatedImageStructure:
    goal = choose_image_goal(target_id=target_id, slot=slot, profile=output_feedback)
    repaired = repair_image_goal(
        goal=goal,
        slot=slot,
        expansion_level=expansion_level,
        seed=seed,
        target_id=target_id,
    )
    return _from_repair(repaired, goal.output_format)


def _from_repair(repaired: ImageRepairResult, output_format: str) -> MutatedImageStructure:
    return MutatedImageStructure(
        image_format=repaired.image_format,
        width=repaired.width,
        height=repaired.height,
        channels=repaired.channels,
        maxval=repaired.maxval,
        payload_delta=repaired.payload_delta,
        comment_style=repaired.comment_style,
        png_interlace=repaired.png_interlace,
        objective=repaired.objective,
        solved_by=repaired.solved_by,
        output_format_goal=output_format,
    )
