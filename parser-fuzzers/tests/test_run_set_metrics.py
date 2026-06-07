from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.run_set_metrics import summarize_run_set


class RunSetMetricsTests(unittest.TestCase):
    def test_summarize_run_set_aggregates_campaigns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_run(root / "campaign-a" / "run-1", cases=10, features=5, crashes=2, unique=1)
            self._write_run(root / "campaign-a" / "run-2", cases=20, features=8, crashes=0, unique=0)
            self._write_run(root / "campaign-b" / "run-3", cases=5, features=4, crashes=1, unique=1)

            payload = summarize_run_set([root / "campaign-a", root / "campaign-b"])

        self.assertEqual(payload["run_count"], 3)
        self.assertEqual(payload["aggregate"]["cases"], 35)
        self.assertEqual(payload["aggregate"]["coverage_features_sum"], 17)
        self.assertEqual(payload["aggregate"]["unique_crashes_sum"], 2)
        self.assertEqual(payload["campaigns"]["campaign-a"]["cases"], 30)

    def _write_run(self, run_dir: Path, *, cases: int, features: int, crashes: int, unique: int) -> None:
        run_dir.mkdir(parents=True)
        (run_dir / "timeline.jsonl").write_text("{}\n", encoding="utf-8")
        (run_dir / "summary.concise.json").write_text(
            json.dumps(
                {
                    "run_id": run_dir.name,
                    "elapsed_sec": 60.0,
                    "cases": cases,
                    "retained_cases": features,
                    "coverage_features": features,
                    "crashes": crashes,
                    "unique_crashes": unique,
                    "timeouts": 0,
                    "skipped": 0,
                    "targets": 1,
                    "stop_reason": "duration",
                }
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
