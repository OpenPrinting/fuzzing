from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.auto_expand import build_auto_expand_plan, discover_campaign_runs, write_auto_expand_plan
from parser_fuzzers.document_harness import make_document


class AutoExpandTests(unittest.TestCase):
    def test_auto_expand_builds_frontier_profile_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "work" / "feedback-campaign" / "20260602-000000"
            case_dir = run_dir / "corpus" / "interesting" / "cups_target" / "case-000001"
            case_dir.mkdir(parents=True)
            document_path = case_dir / "document.ras"
            document_path.write_bytes(make_document("cups_raster_structural_sweep", 1).data)
            (case_dir / "meta.json").write_text(
                json.dumps(
                    {
                        "target_id": "cups_target",
                        "case_id": 1,
                        "document_path": str(document_path),
                        "crashed": False,
                        "timed_out": False,
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "summary.concise.json").write_text(
                json.dumps(
                    {
                        "target_stats": {
                            "cups_target": {
                                "completed": 1000,
                                "retained_cases": 0,
                                "skipped": 0,
                                "timeouts": 0,
                                "crashes": 0,
                            },
                            "suppressed_target": {
                                "completed": 0,
                                "retained_cases": 0,
                                "skipped": 200,
                                "timeouts": 0,
                                "crashes": 0,
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            with (run_dir / "timeline.jsonl").open("w", encoding="utf-8") as handle:
                for case_id in range(10):
                    handle.write(
                        json.dumps(
                            {
                                "target_id": "cups_target",
                                "case_id": case_id,
                                "retained_for_coverage": False,
                                "new_feature_count": 0,
                                "crashed": False,
                                "timed_out": False,
                            }
                        )
                        + "\n"
                    )

            output_profile = root / "work" / "template-feedback" / "auto.json"
            plan_output = root / "work" / "template-feedback" / "auto-plan.json"
            plan = build_auto_expand_plan(
                search_root=root / "work",
                output_profile=output_profile,
                stale_window=10,
                duration_sec=60,
            )
            write_auto_expand_plan(plan, plan_output)

            self.assertEqual(discover_campaign_runs(root / "work"), [run_dir])
            self.assertTrue(output_profile.exists())
            self.assertTrue(plan_output.exists())
            self.assertEqual(plan.expansion_level, 2)
            self.assertEqual(plan.profile_cups, 1)
            self.assertIn("SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL=2", plan.recommended_command)
            self.assertIn("--skip-probe-rate 0.01", plan.recommended_command)
            self.assertEqual(plan.target_actions["suppressed_target"], "probe-runtime-suppressed-family")


if __name__ == "__main__":
    unittest.main()
