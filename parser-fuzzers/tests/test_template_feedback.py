from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.document_harness import make_document
from parser_fuzzers.template_feedback import build_feedback_profile, write_feedback_profile, load_feedback_profile


class TemplateFeedbackTests(unittest.TestCase):
    def test_build_feedback_profile_extracts_interesting_raster_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "corpus" / "interesting" / "cups_target" / "case-000001"
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

            profile = build_feedback_profile(root)

        self.assertEqual(len(profile.cups), 1)
        self.assertEqual(profile.cups[0].fields["width"], 15)
        self.assertIn("bytes_per_line", profile.cups[0].fields)

    def test_feedback_profile_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "quarantine" / "unique" / "pwg-case"
            case_dir.mkdir(parents=True)
            document_path = case_dir / "document.pwg"
            document_path.write_bytes(make_document("pwg_raster_structural_sweep", 2).data)
            (case_dir / "meta.json").write_text(
                json.dumps(
                    {
                        "target_id": "pwg_target",
                        "case_id": 2,
                        "document_path": str(document_path),
                        "crashed": True,
                        "timed_out": False,
                    }
                ),
                encoding="utf-8",
            )
            output = root / "feedback.json"
            write_feedback_profile(build_feedback_profile(root), output)
            loaded = load_feedback_profile(output)

        self.assertEqual(len(loaded.pwg), 1)
        self.assertTrue(loaded.pwg[0].crashed)

    def test_build_feedback_profile_uses_frontier_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = root / "run-old"
            newer = root / "run-new"
            _write_interesting_case(older, "cups_target", 1, "cups_raster_structural_sweep")
            _write_interesting_case(newer, "cups_target", 2, "cups_raster_structural_sweep")
            (newer / "timeline.jsonl").write_text(
                json.dumps(
                    {
                        "target_id": "cups_target",
                        "case_id": 2,
                        "retained_for_coverage": True,
                        "new_feature_count": 4,
                        "reached_expected_filter": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            profile = build_feedback_profile([older, newer], max_cases_per_kind=1)

        self.assertEqual(len(profile.cups), 1)
        self.assertEqual(profile.cups[0].case_id, 2)

    def test_build_feedback_profile_extracts_image_headers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "corpus" / "interesting" / "image_target" / "case-000003"
            case_dir.mkdir(parents=True)
            document_path = case_dir / "document.png"
            document_path.write_bytes(make_document("image_feedback_sweep", 0).data)
            (case_dir / "meta.json").write_text(
                json.dumps(
                    {
                        "target_id": "image_target",
                        "case_id": 3,
                        "document_path": str(document_path),
                        "crashed": False,
                        "timed_out": False,
                    }
                ),
                encoding="utf-8",
            )

            profile = build_feedback_profile(root)

        self.assertEqual(len(profile.images), 1)
        self.assertEqual(profile.images[0].kind, "image")
        self.assertIn("format_id", profile.images[0].fields)
        self.assertIn("width", profile.images[0].fields)

    def test_build_feedback_profile_prefers_deep_non_crashing_image_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_interesting_case(root, "image_target", 0, "image_feedback_sweep", crashed=True)
            _write_interesting_case(root, "image_target", 9, "image_feedback_sweep", crashed=False)
            (root / "timeline.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "target_id": "image_target",
                                "case_id": 0,
                                "retained_for_coverage": True,
                                "new_feature_count": 2,
                                "reached_expected_filter": True,
                                "crashed": True,
                                "semantic_shape": {"path": {"depth_score": 8}},
                            }
                        ),
                        json.dumps(
                            {
                                "target_id": "image_target",
                                "case_id": 9,
                                "retained_for_coverage": True,
                                "new_feature_count": 20,
                                "reached_expected_filter": True,
                                "crashed": False,
                                "semantic_shape": {"path": {"depth_score": 16}},
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            profile = build_feedback_profile(root, max_cases_per_kind=1)

        self.assertEqual(len(profile.images), 1)
        self.assertEqual(profile.images[0].case_id, 9)


def _write_interesting_case(
    root: Path,
    target_id: str,
    case_id: int,
    document_kind: str,
    *,
    crashed: bool = False,
) -> None:
    case_dir = root / "corpus" / "interesting" / target_id / f"case-{case_id:06d}"
    case_dir.mkdir(parents=True)
    extension = ".png" if document_kind == "image_feedback_sweep" else ".ras"
    document_path = case_dir / f"document{extension}"
    document_path.write_bytes(make_document(document_kind, case_id).data)
    (case_dir / "meta.json").write_text(
        json.dumps(
            {
                "target_id": target_id,
                "case_id": case_id,
                "document_path": str(document_path),
                "crashed": crashed,
                "timed_out": False,
            }
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
