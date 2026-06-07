from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.run_metrics import summarize_run_metrics


class RunMetricsTests(unittest.TestCase):
    def test_summarize_run_metrics_combines_summary_dedup_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "summary.concise.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-1",
                        "elapsed_sec": 120.0,
                        "cases": 10,
                        "retained_cases": 4,
                        "coverage_features": 12,
                        "crashes": 2,
                        "unique_crashes": 1,
                        "timeouts": 0,
                        "skipped": 3,
                        "pruned_cases": 2,
                        "targets": 2,
                        "run_dir_bytes": 1073741824,
                        "stop_reason": "duration",
                        "target_stats": {
                            "target-a": {
                                "completed": 5,
                                "retained_cases": 3,
                                "crashes": 0,
                                "timeouts": 0,
                                "runtime_suppressed": 0,
                            }
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "dedup.json").write_text(
                json.dumps(
                    {
                        "crash_records": 2,
                        "unique_crashes": 1,
                        "clusters": [
                            {
                                "target_id": "target-b",
                                "count": 2,
                                "signature": "sig",
                                "representative_work_dir": "case",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "timeline.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"document_description": "x via y/z3-structure-avoid"}),
                        json.dumps({"new_crash_signature": True}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload = summarize_run_metrics(root)

        self.assertEqual(payload["run"]["cases"], 10)
        self.assertEqual(payload["derived"]["timeline_records"], 2)
        self.assertEqual(payload["derived"]["z3_structure_avoid_records"], 1)
        self.assertEqual(payload["derived"]["new_crash_signature_records"], 1)
        self.assertEqual(payload["derived"]["retained_per_min"], 2.0)
        self.assertEqual(payload["derived"]["cases_per_sec"], 0.083)
        self.assertEqual(payload["standard"]["execs_done"], 10)
        self.assertEqual(payload["standard"]["execs_per_sec"], 0.083)
        self.assertEqual(payload["standard"]["coverage_features_per_hour"], 360.0)
        self.assertEqual(payload["standard"]["run_dir_gb"], 1.0)
        self.assertEqual(payload["standard"]["pruned_cases"], 2)
        self.assertEqual(payload["dedup"]["unique_crash_signatures"], 1)
        self.assertEqual(payload["target_stats"]["target-a"]["retained_density"], 0.6)


if __name__ == "__main__":
    unittest.main()
