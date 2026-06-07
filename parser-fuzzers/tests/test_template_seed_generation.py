from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.afl_integration.template_seed_generation import generate_template_seeds


class TemplateSeedGenerationTests(unittest.TestCase):
    def test_generates_structured_documents_without_target_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "seeds"
            summary = generate_template_seeds(
                document_kind="pwg_raster_feedback_sweep",
                target_id="template_probe_pwg",
                output_dir=out_dir,
                count=4,
                extensions=[".pwg"],
            )

            self.assertEqual(summary.generated, 4)
            seed_files = sorted(out_dir.glob("*.pwg"))
            self.assertEqual(len(seed_files), 4)
            self.assertTrue(all(path.read_bytes().startswith(b"2SaR") for path in seed_files))
            ordinary_files = sorted(path.name for path in out_dir.iterdir() if not path.name.startswith("."))
            self.assertEqual(ordinary_files, [path.name for path in seed_files])
            manifest = json.loads((out_dir.parent / "seeds-template_seed_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["document_kind"], "pwg_raster_feedback_sweep")
            self.assertEqual(manifest["target_id"], "template_probe_pwg")


if __name__ == "__main__":
    unittest.main()
