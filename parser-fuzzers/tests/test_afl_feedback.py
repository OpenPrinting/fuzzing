from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.afl_feedback import import_afl_artifacts, resolve_afl_instance_dir


class AFLFeedbackImportTests(unittest.TestCase):
    def test_imports_queue_and_crashes_as_runner_feedback_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance = root / "out" / "default"
            queue = instance / "queue"
            crashes = instance / "crashes"
            queue.mkdir(parents=True)
            crashes.mkdir(parents=True)
            (queue / "id:000000,orig:seed").write_bytes(b"2SaRqueue")
            (queue / "id:000001,dup").write_bytes(b"2SaRqueue")
            (crashes / "id:000000,sig:11").write_bytes(b"2SaRcrash")
            (crashes / "README.txt").write_text("metadata\n", encoding="utf-8")

            output = root / "feedback"
            summary = import_afl_artifacts(
                afl_out=root,
                target_id="pwg_to_pdf_feedback_f30",
                output_run_dir=output,
                extension=".pwg",
                queue_limit=16,
                crash_limit=16,
                queue_mode="all",
            )

            self.assertEqual(summary.queue_imported, 1)
            self.assertEqual(summary.crashes_imported, 1)
            self.assertEqual(summary.duplicates_skipped, 1)
            self.assertTrue(
                (
                    output
                    / "corpus"
                    / "interesting"
                    / "pwg_to_pdf_feedback_f30"
                    / "case-000000"
                    / "meta.json"
                ).exists()
            )
            self.assertTrue(
                (
                    output
                    / "quarantine"
                    / "unique"
                    / "pwg_to_pdf_feedback_f30-afl-case-000001"
                    / "document.pwg"
                ).exists()
            )
            self.assertTrue((output / "timeline.jsonl").exists())

    def test_default_import_skips_original_seed_queue_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            queue = root / "out" / "queue"
            crashes = root / "out" / "crashes"
            queue.mkdir(parents=True)
            crashes.mkdir(parents=True)
            (queue / "id:000000,time:0,execs:0,orig:seed").write_bytes(b"2SaRseed")
            (queue / "id:000001,src:000000,time:10,execs:7,op:havoc").write_bytes(b"2SaRnew")

            summary = import_afl_artifacts(
                afl_out=root / "out",
                target_id="pwg_to_pdf_feedback_f30",
                output_run_dir=root / "feedback",
                extension=".pwg",
            )

            self.assertEqual(summary.queue_mode, "new")
            self.assertEqual(summary.queue_imported, 1)
            imported_sources = [item.source_path for item in summary.imported]
            self.assertTrue(any("src:000000" in path for path in imported_sources))
            self.assertFalse(any("orig:seed" in path for path in imported_sources))

    def test_resolves_campaign_or_out_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "out" / "default" / "queue").mkdir(parents=True)
            self.assertEqual(resolve_afl_instance_dir(root), root / "out" / "default")
            self.assertEqual(resolve_afl_instance_dir(root / "out"), root / "out" / "default")


if __name__ == "__main__":
    unittest.main()
