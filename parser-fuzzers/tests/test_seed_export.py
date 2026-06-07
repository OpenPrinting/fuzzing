from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.afl_integration.seed_export import export_template_seeds


class SeedExportTests(unittest.TestCase):
    def test_exports_retained_documents_as_afl_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "run" / "corpus" / "interesting" / "pwg_target" / "case-000001"
            case_dir.mkdir(parents=True)
            (case_dir / "document.pwg").write_bytes(b"RaS2")
            (case_dir / "document.pdf").write_bytes(b"%PDF")
            out_dir = root / "seeds"

            summary = export_template_seeds(
                run_dir=root / "run",
                output_dir=out_dir,
                target_ids=["pwg_target"],
                extensions=["pwg"],
            )

            self.assertEqual(summary.exported, 1)
            exported = sorted(out_dir.glob("*.pwg"))
            self.assertEqual(len(exported), 1)
            self.assertEqual(exported[0].read_bytes(), b"RaS2")
            ordinary_files = sorted(path.name for path in out_dir.iterdir() if not path.name.startswith("."))
            self.assertEqual(ordinary_files, [exported[0].name])
            manifest_path = out_dir.parent / "seeds-seed_export_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["exported_by_target"], {"pwg_target": 1})
            self.assertEqual(manifest["manifest_path"], str(manifest_path))


if __name__ == "__main__":
    unittest.main()
