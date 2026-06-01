from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smt_fuzzer.document_harness import HEADER_SIZE, make_document


class DocumentHarnessTests(unittest.TestCase):
    def test_text_document_is_plain_seed(self) -> None:
        document = make_document("text", 0)
        self.assertEqual(document.mime, "text/plain")
        self.assertIn(b"SMT multi-target", document.data)

    def test_cups_raster_has_magic_and_page_data(self) -> None:
        document = make_document("cups_raster_mode10", 0)
        self.assertEqual(document.data[:4], b"3SaR")
        self.assertGreater(len(document.data), HEADER_SIZE)

    def test_cups_raster_boundary_sweep_has_magic(self) -> None:
        document = make_document("cups_raster_boundary_sweep", 3)
        self.assertEqual(document.data[:4], b"3SaR")
        self.assertGreater(len(document.data), HEADER_SIZE)

    def test_pwg_raster_has_magic_and_page_data(self) -> None:
        document = make_document("pwg_raster_boundary_sweep", 1)
        self.assertEqual(document.data[:4], b"2SaR")
        self.assertGreater(len(document.data), HEADER_SIZE)

    def test_pwg_raster_boundary_sweep_has_magic(self) -> None:
        document = make_document("pwg_raster_boundary_sweep", 7)
        self.assertEqual(document.data[:4], b"2SaR")
        self.assertGreater(len(document.data), HEADER_SIZE)

    def test_coverage_raster_sweep_can_generate_multipage_input(self) -> None:
        document = make_document("cups_raster_coverage_sweep", 1)
        self.assertEqual(document.data[:4], b"3SaR")
        self.assertGreater(len(document.data), HEADER_SIZE * 2)

    def test_coverage_pwg_sweep_has_magic(self) -> None:
        document = make_document("pwg_raster_coverage_sweep", 1)
        self.assertEqual(document.data[:4], b"2SaR")
        self.assertGreater(len(document.data), HEADER_SIZE * 2)

    def test_pdf_coverage_sweep_has_pdf_magic(self) -> None:
        document = make_document("pdf_coverage_sweep", 0)
        self.assertEqual(document.mime, "application/pdf")
        self.assertTrue(document.data.startswith(b"%PDF-"))
        self.assertIn(b"xref", document.data)

    def test_image_coverage_sweep_includes_pnm_and_png(self) -> None:
        png = make_document("image_coverage_sweep", 0)
        pnm = make_document("image_coverage_sweep", 2)

        self.assertTrue(pnm.data.startswith(b"P6"))
        self.assertTrue(png.data.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_text_and_command_coverage_sweeps(self) -> None:
        text = make_document("text_coverage_sweep", 2)
        command = make_document("command_coverage_sweep", 0)

        self.assertEqual(text.mime, "text/plain")
        self.assertEqual(command.mime, "application/vnd.cups-command")
        self.assertTrue(command.data.startswith(b"#CUPS-COMMAND"))

    def test_postscript_coverage_sweep_has_magic(self) -> None:
        document = make_document("postscript_coverage_sweep", 1)
        self.assertEqual(document.mime, "application/postscript")
        self.assertTrue(document.data.startswith(b"%!PS"))


if __name__ == "__main__":
    unittest.main()
