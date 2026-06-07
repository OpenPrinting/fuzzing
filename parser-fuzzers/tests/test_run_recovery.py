from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.run_recovery import recover_run_summary


class RunRecoveryTests(unittest.TestCase):
    def test_recovers_concise_summary_from_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "run_manifest.json").write_text(
                json.dumps(
                    {
                        "run_id": "test-run",
                        "workers": 2,
                        "timeout_sec": 5,
                        "duration_sec": 60,
                        "targets": [{"id": "image_to_ps"}],
                        "runtime_skip": True,
                    }
                ),
                encoding="utf-8",
            )
            records = [
                {
                    "target_id": "image_to_ps",
                    "case_id": 0,
                    "crashed": True,
                    "timed_out": False,
                    "oracle": "stderr crash/sanitizer",
                    "new_crash_signature": True,
                    "retained_for_coverage": True,
                    "new_feature_count": 3,
                },
                {
                    "target_id": "image_to_ps",
                    "case_id": 1,
                    "skipped": True,
                    "skip_reason": "runtime-known-crash-shape:asan",
                    "crashed": False,
                    "timed_out": False,
                },
            ]
            with (root / "timeline.jsonl").open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")

            summary = recover_run_summary(root)

            self.assertEqual(summary["cases"], 1)
            self.assertEqual(summary["crashes"], 1)
            self.assertEqual(summary["skipped"], 1)
            self.assertEqual(summary["unique_crashes"], 1)
            self.assertEqual(summary["coverage_features"], 3)
            self.assertTrue((root / "summary.concise.json").exists())
            self.assertTrue((root / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
