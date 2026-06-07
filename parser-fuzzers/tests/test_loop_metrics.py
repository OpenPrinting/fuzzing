from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.loop_metrics import write_standard_loop_metrics


class LoopMetricsTests(unittest.TestCase):
    def test_summarizes_template_afl_feedback_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "campaign"
            template_run = campaign / "template" / "run"
            feedback_run = campaign / "feedback-template" / "run"
            template_run.mkdir(parents=True)
            feedback_run.mkdir(parents=True)
            _write_metrics(template_run / "standard_metrics.json", execs=100, features=20, corpus=7)
            _write_metrics(feedback_run / "standard_metrics.json", execs=80, features=25, corpus=9)
            _write_metrics(campaign / "afl-standard-metrics.json", execs=1000, features=12, corpus=30, crashes=1)
            (campaign / "seed-export.json").write_text(
                json.dumps({"exported": 4, "targets": ["t"], "extensions": [".pwg"]}),
                encoding="utf-8",
            )
            (campaign / "afl-import.json").write_text(
                json.dumps({"imported": [{"source": "afl-queue"}, {"source": "afl-crash"}], "crashes_imported": 1}),
                encoding="utf-8",
            )
            (campaign / "feedback-profile-build.json").write_text(
                json.dumps({"pwg_seeds": 2}),
                encoding="utf-8",
            )
            (campaign / "loop_manifest.json").write_text(
                json.dumps({"template_run": str(template_run), "feedback_run": str(feedback_run)}),
                encoding="utf-8",
            )

            payload = write_standard_loop_metrics(campaign)

            self.assertEqual(payload["summary"]["template_features"], 20)
            self.assertEqual(payload["summary"]["afl_crashes"], 1)
            self.assertEqual(payload["summary"]["feedback_feature_delta_vs_template"], 5)
            self.assertEqual(payload["afl_import"]["source_counts"], {"afl-crash": 1, "afl-queue": 1})
            self.assertTrue((campaign / "loop_standard_metrics.json").exists())


def _write_metrics(path: Path, *, execs: int, features: int, corpus: int, crashes: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "standard": {
                    "execs_done": execs,
                    "coverage_features": features,
                    "corpus_count": corpus,
                    "crashes": crashes,
                    "timeouts": 0,
                }
            }
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
