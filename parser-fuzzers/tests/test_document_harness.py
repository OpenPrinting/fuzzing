from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.document_harness import HEADER_SIZE, make_document


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
        document = make_document("pwg_raster_resolution_stress", 1)
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

    def test_structural_sweeps_have_magic(self) -> None:
        cups = make_document("cups_raster_structural_sweep", 3)
        pwg = make_document("pwg_raster_structural_sweep", 4)

        self.assertEqual(cups.data[:4], b"3SaR")
        self.assertEqual(pwg.data[:4], b"2SaR")
        self.assertGreater(len(cups.data), HEADER_SIZE)
        self.assertGreater(len(pwg.data), HEADER_SIZE)

    def test_pdf_coverage_sweep_has_pdf_magic(self) -> None:
        document = make_document("pdf_coverage_sweep", 0)
        self.assertEqual(document.mime, "application/pdf")
        self.assertTrue(document.data.startswith(b"%PDF-"))
        self.assertIn(b"xref", document.data)

    def test_pdf_semantic_sweep_exercises_pdf_features(self) -> None:
        documents = [make_document("pdf_semantic_sweep", index) for index in range(8)]
        payloads = [document.data for document in documents]

        self.assertTrue(all(document.mime == "application/pdf" for document in documents))
        self.assertTrue(all(payload.startswith(b"%PDF-") for payload in payloads))
        self.assertTrue(all(b"xref" in payload for payload in payloads))
        self.assertTrue(any(b"/Rotate 90" in payload for payload in payloads))
        self.assertTrue(any(b"/Filter /FlateDecode" in payload for payload in payloads))
        self.assertTrue(any(b"/XObject" in payload for payload in payloads))

    def test_image_coverage_sweep_includes_pnm_and_png(self) -> None:
        png = make_document("image_coverage_sweep", 0)
        pnm = make_document("image_coverage_sweep", 2)

        self.assertTrue(pnm.data.startswith(b"P6"))
        self.assertTrue(png.data.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_image_feedback_sweep_includes_structured_images(self) -> None:
        documents = [make_document("image_feedback_sweep", index) for index in range(12)]
        prefixes = {document.data[:2] for document in documents}

        self.assertTrue(any(document.data.startswith(b"\x89PNG\r\n\x1a\n") for document in documents))
        self.assertTrue(any(prefix in {b"P4", b"P5", b"P6"} for prefix in prefixes))
        self.assertTrue(all(document.mime in {"image/png", "image/x-portable-anymap"} for document in documents))

    def test_text_and_command_coverage_sweeps(self) -> None:
        text = make_document("text_coverage_sweep", 2)
        command = make_document("command_coverage_sweep", 0)

        self.assertEqual(text.mime, "text/plain")
        self.assertEqual(command.mime, "application/vnd.cups-command")
        self.assertTrue(command.data.startswith(b"#CUPS-COMMAND"))

    def test_text_and_command_semantic_sweeps(self) -> None:
        text_documents = [make_document("text_semantic_sweep", index) for index in range(10)]
        command_documents = [make_document("command_semantic_sweep", index) for index in range(10)]

        self.assertTrue(all(document.mime == "text/plain" for document in text_documents))
        self.assertTrue(any(b"\f" in document.data for document in text_documents))
        self.assertTrue(any(b"\x1b" in document.data for document in text_documents))
        self.assertTrue(all(document.data.startswith(b"#CUPS-COMMAND") for document in command_documents))
        self.assertTrue(any(b"SetAlignment" in document.data for document in command_documents))

    def test_postscript_coverage_sweep_has_magic(self) -> None:
        document = make_document("postscript_coverage_sweep", 1)
        self.assertEqual(document.mime, "application/postscript")
        self.assertTrue(document.data.startswith(b"%!PS"))

    def test_postscript_semantic_sweep_exercises_language_features(self) -> None:
        documents = [make_document("postscript_semantic_sweep", index) for index in range(8)]
        payloads = [document.data for document in documents]

        self.assertTrue(all(document.mime == "application/postscript" for document in documents))
        self.assertTrue(all(payload.startswith(b"%!PS") for payload in payloads))
        self.assertTrue(any(b"setpagedevice" in payload for payload in payloads))
        self.assertTrue(any(b" image" in payload for payload in payloads))


if __name__ == "__main__":
    unittest.main()
