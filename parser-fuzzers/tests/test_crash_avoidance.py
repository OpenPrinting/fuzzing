from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_fuzzers.constraint_repair import repair_image_goal
from parser_fuzzers.crash_avoidance import preferred_crash_avoidance_profile
from parser_fuzzers.format_specs import image_goals_for_target
from parser_fuzzers.output_feedback import choose_image_goal


class CrashAvoidanceTests(unittest.TestCase):
    def test_crash_hazard_profile_loads_suppressed_image_hazards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = _write_state(Path(tmp))
            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_CRASH_AVOIDANCE": "1",
                    "SMT_FUZZER_CRASH_AVOIDANCE_STATE": str(state_path),
                },
                clear=False,
            ):
                profile = preferred_crash_avoidance_profile()

        self.assertEqual(len(profile.hazards), 1)
        self.assertEqual(profile.hazards[0].target_id, "image_to_imagetoraster_feedback")
        self.assertEqual(profile.hazards[0].image_format, "png_rgb")
        self.assertEqual(profile.hazards[0].payload, "exact")

    def test_repair_image_goal_avoids_exact_old_hazard(self) -> None:
        goal = next(
            item
            for item in image_goals_for_target("image_to_imagetoraster_feedback")
            if item.name == "raster-rgb24"
        )
        with tempfile.TemporaryDirectory() as tmp:
            state_path = _write_state(Path(tmp))
            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_CRASH_AVOIDANCE": "1",
                    "SMT_FUZZER_CRASH_AVOIDANCE_STATE": str(state_path),
                },
                clear=False,
            ):
                repaired = repair_image_goal(
                    goal=goal,
                    slot=0,
                    expansion_level=3,
                    target_id="image_to_imagetoraster_feedback",
                )

        self.assertEqual(repaired.payload_delta, 0)
        self.assertEqual(repaired.png_interlace, 0)
        self.assertNotEqual(repaired.image_format, "png_rgb")
        self.assertIn(repaired.solved_by, {"z3-structure-avoid", "fallback-structure"})

    def test_generalized_avoidance_applies_across_neighbor_objectives(self) -> None:
        goal = next(
            item
            for item in image_goals_for_target("image_to_imagetops_feedback")
            if item.name == "ps-commented-pnm"
        )
        with tempfile.TemporaryDirectory() as tmp:
            state_path = _write_state(
                Path(tmp),
                target_id="image_to_imagetops_feedback",
                objective="postscript:ps-wide-maxval",
                image_format="ppm",
                signature="SUMMARY: AddressSanitizer: SEGV example/image.c:75 in close_image",
            )
            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_CRASH_AVOIDANCE": "1",
                    "SMT_FUZZER_CRASH_AVOIDANCE_GENERALIZE": "1",
                    "SMT_FUZZER_CRASH_AVOIDANCE_STATE": str(state_path),
                },
                clear=False,
            ):
                repaired = repair_image_goal(
                    goal=goal,
                    slot=0,
                    expansion_level=3,
                    target_id="image_to_imagetops_feedback",
                )

        self.assertEqual(repaired.payload_delta, 0)
        self.assertEqual(repaired.png_interlace, 0)
        self.assertNotEqual(repaired.image_format, "ppm")
        self.assertIn(repaired.solved_by, {"z3-structure-avoid", "fallback-structure"})

    def test_goal_selection_deprioritizes_old_crash_objective(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = _write_state(
                Path(tmp),
                target_id="image_to_imagetops_feedback",
                objective="postscript:ps-showpage-image",
                image_format="png_rgb",
                signature="SUMMARY: AddressSanitizer: SEGV example/image.c:75 in close_image",
            )
            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_AUTO_DIMENSIONS": "0",
                    "SMT_FUZZER_CRASH_AVOIDANCE": "1",
                    "SMT_FUZZER_CRASH_AVOIDANCE_STATE": str(state_path),
                },
                clear=False,
            ):
                goal = choose_image_goal(
                    target_id="image_to_imagetops_feedback_semantic",
                    slot=0,
                )

        self.assertNotEqual(goal.name, "ps-showpage-image")


def _write_state(
    root: Path,
    *,
    target_id: str = "image_to_imagetoraster_feedback",
    objective: str = "cups-raster:raster-rgb24",
    image_format: str = "png_rgb",
    signature: str = (
        "SUMMARY: AddressSanitizer: heap-buffer-overflow "
        "example/image_scale.c:123 in sample_scale"
    ),
) -> Path:
    state_path = root / "discovery_state.json"
    state_path.write_text(
        json.dumps(
            {
                "suppressed_case_hazards": [
                    {
                        "hazard": (
                            f"target:{target_id}|"
                            "ppd:coverage_options|"
                            "doc:image_feedback_sweep|"
                            f"fmt:{image_format}|"
                            f"objective:{objective}|"
                            "payload:exact|"
                            "interlace:0"
                        ),
                        "signature": signature,
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return state_path


if __name__ == "__main__":
    unittest.main()
