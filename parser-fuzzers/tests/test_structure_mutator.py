from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_fuzzers.constraint_repair import repair_image_goal
from parser_fuzzers.dimension_expander import expand_image_goals
from parser_fuzzers.format_specs import image_goals_for_target
from parser_fuzzers.image_templates import image_feedback_instance
from parser_fuzzers.output_feedback import build_output_feedback_profile, choose_image_goal
from parser_fuzzers.structure_mutator import mutate_image_structure


class StructureMutatorTests(unittest.TestCase):
    def test_output_feedback_counts_objective_output_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "timeline.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "target_id": "image_to_imagetopdf_feedback",
                                "document_description": "feedback-driven image sweep via pdf:pdf-single-image/z3-structure",
                                "semantic_shape": {
                                    "output": {
                                        "format": "pdf",
                                        "structure": "pdf:1.3|obj:5-16|stream:1|page:1|image:1",
                                    }
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "target_id": "image_to_imagetopdf_feedback",
                                "document_description": "feedback-driven image sweep via pdf-wide-image/z3-structure",
                                "semantic_shape": {"output": {"format": "empty", "structure": "empty"}},
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            profile = build_output_feedback_profile(run_dir)
            goal = choose_image_goal(
                target_id="image_to_imagetopdf_feedback",
                slot=0,
                profile=profile,
            )

        self.assertEqual(profile.objective_output_counts["image_to_imagetopdf_feedback|pdf-single-image|pdf"], 1)
        self.assertNotEqual(goal.name, "pdf-single-image")

    def test_repair_image_goal_satisfies_goal_constraints(self) -> None:
        goal = next(item for item in image_goals_for_target("image_to_imagetopdf_feedback") if item.name == "pdf-wide-image")
        repaired = repair_image_goal(goal=goal, slot=3, expansion_level=3)

        self.assertIn(repaired.image_format, goal.allowed_formats)
        self.assertGreaterEqual(repaired.width, repaired.height * 4)
        self.assertEqual(repaired.payload_delta, 0)
        self.assertEqual(repaired.objective, "pdf-wide-image")

    def test_structure_mutator_selects_target_specific_output_goal(self) -> None:
        mutated = mutate_image_structure(
            target_id="image_to_imagetoraster_feedback",
            slot=0,
            expansion_level=3,
        )

        self.assertEqual(mutated.output_format_goal, "cups-raster")
        self.assertTrue(mutated.objective.startswith("raster-"))
        self.assertGreaterEqual(mutated.width * mutated.height, 1)

    def test_target_goal_sets_include_expanded_combinations(self) -> None:
        pdf_names = {goal.name for goal in image_goals_for_target("image_to_imagetopdf_feedback")}
        ps_names = {goal.name for goal in image_goals_for_target("image_to_imagetops_feedback")}
        raster_names = {goal.name for goal in image_goals_for_target("image_to_imagetoraster_feedback")}

        self.assertIn("pdf-interlaced-png", pdf_names)
        self.assertIn("pdf-large-rgb", pdf_names)
        self.assertIn("ps-bitmap-image", ps_names)
        self.assertIn("ps-large-rgb", ps_names)
        self.assertIn("raster-bitmap-rows", raster_names)
        self.assertIn("raster-large-rgb", raster_names)

    def test_auto_dimension_expander_generates_semantic_variants(self) -> None:
        goals = image_goals_for_target("image_to_imagetopdf_feedback")
        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_AUTO_DIMENSIONS": "1",
                "SMT_FUZZER_AUTO_DIMENSION_BUDGET": "64",
            },
            clear=False,
        ):
            expanded = expand_image_goals(
                target_id="image_to_imagetopdf_feedback",
                goals=goals,
                slot=0,
            )

        auto_goals = [goal for goal in expanded if goal.name.startswith("auto-")]
        auto_names = {goal.name for goal in auto_goals}
        payload_policies = {goal.payload_policy for goal in auto_goals}
        comment_styles = {goal.comment_style for goal in auto_goals}
        interlace_values = {goal.png_interlace for goal in auto_goals}

        self.assertGreater(len(expanded), len(goals))
        self.assertIn("short", payload_policies)
        self.assertIn("extra", payload_policies)
        self.assertIn(3, comment_styles)
        self.assertIn(1, interlace_values)
        self.assertTrue(any(name.endswith("-wide-maxval") for name in auto_names))
        self.assertTrue(any(name.endswith("-large-area") for name in auto_names))

    def test_auto_dimension_choice_can_enter_structure_repair(self) -> None:
        base_goals = image_goals_for_target("image_to_imagetopdf_feedback")
        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_AUTO_DIMENSIONS": "1",
                "SMT_FUZZER_AUTO_DIMENSION_BUDGET": "64",
            },
            clear=False,
        ):
            goal = choose_image_goal(
                target_id="image_to_imagetopdf_feedback",
                slot=len(base_goals),
            )
            repaired = repair_image_goal(goal=goal, slot=17, expansion_level=3)

        self.assertTrue(goal.name.startswith("auto-"))
        self.assertIn(repaired.image_format, goal.allowed_formats)
        self.assertGreaterEqual(repaired.width, goal.min_width)
        self.assertGreaterEqual(repaired.height, goal.min_height)
        self.assertGreaterEqual(repaired.width * repaired.height, goal.min_area)
        self.assertEqual(repaired.objective, goal.name)

    def test_image_feedback_instance_uses_structure_mutator_when_enabled(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_STRUCTURE_MUTATOR": "1",
                "SMT_FUZZER_TARGET_ID": "image_to_imagetopdf_feedback",
                "SMT_FUZZER_IMAGE_EXPANSION_LEVEL": "3",
                "SMT_FUZZER_IMAGE_CYCLE_EPOCHS": "1",
            },
            clear=False,
        ):
            instance = image_feedback_instance(0)

        self.assertTrue(instance.objective.startswith("pdf:"))
        self.assertIn(instance.solved_by, {"z3-structure", "fallback-structure"})
        self.assertGreaterEqual(instance.width, 1)


if __name__ == "__main__":
    unittest.main()
