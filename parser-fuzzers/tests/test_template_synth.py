from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from parser_fuzzers.document_harness import (
    OFF_CUPS_BITS_PER_PIXEL,
    OFF_CUPS_BYTES_PER_LINE,
    OFF_CUPS_COLOR_SPACE,
    OFF_CUPS_HEIGHT,
    OFF_CUPS_ROW_COUNT,
    OFF_CUPS_WIDTH,
    OFF_HW_RESOLUTION,
    make_document,
)
from parser_fuzzers.image_templates import image_feedback_instance
from parser_fuzzers.ppd_templates import PAGE_SIZES, make_ppd
from parser_fuzzers.template_synth import (
    synthesize_cups_raster_slots,
    synthesize_image_slots,
    synthesize_ppd_slots,
    synthesize_pwg_raster_slots,
)
from parser_fuzzers.structured_templates import cups_structural_instance, pwg_structural_instance


class TemplateSynthTests(unittest.TestCase):
    def test_cups_raster_slots_fill_document_header(self) -> None:
        slots = synthesize_cups_raster_slots(17)
        document = make_document("cups_raster_coverage_sweep", 17)
        header = document.data[4 : 4 + 1796]

        self.assertEqual(_u32(header, OFF_CUPS_WIDTH), slots.width)
        self.assertEqual(_u32(header, OFF_CUPS_HEIGHT), slots.height)
        self.assertEqual(_u32(header, OFF_CUPS_BITS_PER_PIXEL), slots.bits_per_pixel)
        self.assertEqual(_u32(header, OFF_CUPS_COLOR_SPACE), slots.color_space)
        self.assertGreaterEqual(_u32(header, OFF_CUPS_BYTES_PER_LINE), (slots.width * slots.bits_per_pixel + 7) // 8)

    def test_pwg_slots_fill_document_header(self) -> None:
        slots = synthesize_pwg_raster_slots(23)
        document = make_document("pwg_raster_coverage_sweep", 23)
        header = document.data[4 : 4 + 1796]

        self.assertEqual(_u32(header, OFF_CUPS_WIDTH), slots.width)
        self.assertEqual(_u32(header, OFF_CUPS_HEIGHT), slots.height)
        self.assertEqual(_u32(header, OFF_CUPS_BITS_PER_PIXEL), slots.bits_per_pixel)
        self.assertEqual(_u32(header, OFF_HW_RESOLUTION), slots.x_res & 0xFFFFFFFF)

    def test_structural_cups_template_fills_relation_fields(self) -> None:
        instance = cups_structural_instance(19)
        document = make_document("cups_raster_structural_sweep", 19)
        header = document.data[4 : 4 + 1796]

        self.assertEqual(_u32(header, OFF_CUPS_WIDTH), instance.get("width"))
        self.assertEqual(_u32(header, OFF_CUPS_HEIGHT), instance.get("height"))
        self.assertEqual(_u32(header, OFF_CUPS_BYTES_PER_LINE), instance.get("bytes_per_line"))
        self.assertEqual(_u32(header, OFF_CUPS_ROW_COUNT), instance.get("row_count"))
        self.assertGreaterEqual(len(document.data), 4 + 1796 + instance.get("bytes_per_line"))

    def test_structural_pwg_template_fills_relation_fields(self) -> None:
        instance = pwg_structural_instance(23)
        document = make_document("pwg_raster_structural_sweep", 23)
        header = document.data[4 : 4 + 1796]

        self.assertEqual(_u32(header, OFF_CUPS_WIDTH), instance.get("width"))
        self.assertEqual(_u32(header, OFF_CUPS_HEIGHT), instance.get("height"))
        self.assertEqual(_u32(header, OFF_CUPS_BITS_PER_PIXEL), instance.get("bits_per_pixel"))
        self.assertEqual(_u32(header, OFF_CUPS_BYTES_PER_LINE), instance.get("bytes_per_line"))
        self.assertEqual(_u32(header, OFF_CUPS_ROW_COUNT), instance.get("row_count"))

    def test_feedback_templates_use_profile_seed_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = os.path.join(tmp, "feedback.json")
            _write_feedback_profile_fixture(profile_path)

            with patch.dict("os.environ", {"SMT_FUZZER_TEMPLATE_FEEDBACK": profile_path}):
                cups = make_document("cups_raster_feedback_sweep", 1)
                pwg = make_document("pwg_raster_feedback_sweep", 1)

        cups_header = cups.data[4 : 4 + 1796]
        pwg_header = pwg.data[4 : 4 + 1796]
        self.assertEqual(cups.data[:4], b"3SaR")
        self.assertEqual(pwg.data[:4], b"2SaR")
        self.assertIn(_u32(cups_header, OFF_CUPS_WIDTH), {31, 32, 33})
        self.assertGreaterEqual(_u32(cups_header, OFF_CUPS_BYTES_PER_LINE), 1)
        self.assertIn(_u32(pwg_header, OFF_CUPS_WIDTH), {63, 64, 65})

    def test_feedback_expansion_level_enables_wider_variants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = os.path.join(tmp, "feedback.json")
            _write_feedback_profile_fixture(profile_path)

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_TEMPLATE_FEEDBACK": profile_path,
                    "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": "2",
                },
            ):
                cups = make_document("cups_raster_feedback_sweep", 10)

        self.assertIn("wide_pad_16", cups.description)

    def test_afl_feedback_seed_fields_are_sanitized_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = os.path.join(tmp, "afl-feedback.json")
            _write_huge_afl_feedback_fixture(profile_path)

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_TEMPLATE_FEEDBACK": profile_path,
                    "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": "2",
                },
            ):
                document = make_document("pwg_raster_feedback_sweep", 0)

        header = document.data[4 : 4 + 1796]
        self.assertLess(len(document.data), 1024 * 1024)
        self.assertLessEqual(_u32(header, OFF_CUPS_HEIGHT), 16)
        self.assertLessEqual(_u32(header, OFF_CUPS_BYTES_PER_LINE), 4096)
        self.assertLessEqual(_u32(header, OFF_CUPS_ROW_COUNT), 64)

    def test_image_slots_fill_image_template(self) -> None:
        slots = synthesize_image_slots(5)
        document = make_document("image_coverage_sweep", 5)

        if slots.image_format.startswith("png"):
            self.assertTrue(document.data.startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertEqual(struct.unpack(">I", document.data[16:20])[0], slots.width)
            self.assertEqual(struct.unpack(">I", document.data[20:24])[0], slots.height)
        else:
            self.assertTrue(document.data[:1] == b"P")
            self.assertIn(str(slots.width).encode("ascii"), document.data.splitlines()[1])

    def test_image_feedback_expansion_includes_post_scaling_valid_objective(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_IMAGE_EXPANSION_LEVEL": "3",
                "SMT_FUZZER_IMAGE_VALID_BIAS": "1",
                "SMT_FUZZER_IMAGE_CYCLE_EPOCHS": "1",
            },
            clear=False,
        ):
            instances = [image_feedback_instance(index) for index in range(160)]

        deep = [item for item in instances if item.objective == "post_scaling_valid"]
        self.assertTrue(deep)
        self.assertTrue(any(item.width * item.height >= 3072 for item in deep))
        self.assertTrue(all(item.payload_delta == 0 for item in deep))

    def test_ppd_slots_fill_page_size_and_options(self) -> None:
        slots = synthesize_ppd_slots(19)
        ppd = make_ppd("pdftoraster_coverage_options", 19)
        page_name = PAGE_SIZES[slots.page_size_index][0]

        self.assertIn(f"*DefaultPageSize: {page_name}", ppd)
        self.assertIn("*OpenUI *ColorModel", ppd)
        self.assertIn("*OpenUI *PrintQuality", ppd)


def _u32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]


def _write_feedback_profile_fixture(profile_path: str) -> None:
    with open(profile_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "source_run_dir": "test",
                "cups": [
                    {
                        "kind": "cups",
                        "source": "test",
                        "target_id": "cups_raster_to_rastertopclx_structural",
                        "case_id": 1,
                        "document_path": "",
                        "crashed": True,
                        "timed_out": False,
                        "fields": {
                            "width": 31,
                            "height": 5,
                            "bits_per_pixel": 8,
                            "bytes_per_line": 30,
                            "row_count": 5,
                            "payload_rows": 5,
                            "color_space": 3,
                            "num_colors": 1,
                            "color_order": 0,
                            "compression": 10,
                            "x_res": 360,
                            "y_res": 1200,
                        },
                    }
                ],
                "pwg": [
                    {
                        "kind": "pwg",
                        "source": "test",
                        "target_id": "pwg_to_pclm_structural",
                        "case_id": 2,
                        "document_path": "",
                        "crashed": False,
                        "timed_out": False,
                        "fields": {
                            "width": 63,
                            "height": 4,
                            "bits_per_pixel": 16,
                            "bytes_per_line": 126,
                            "row_count": 4,
                            "payload_rows": 4,
                            "color_space": 18,
                            "num_colors": 1,
                            "color_order": 0,
                            "compression": 0,
                            "x_res": 600,
                            "y_res": 1200,
                        },
                    }
                ],
            },
            handle,
        )


def _write_huge_afl_feedback_fixture(profile_path: str) -> None:
    with open(profile_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "source_run_dir": "afl",
                "cups": [],
                "pwg": [
                    {
                        "kind": "pwg",
                        "source": "afl-crash",
                        "target_id": "pwg_to_pdf_feedback_f30",
                        "case_id": 134,
                        "document_path": "",
                        "crashed": True,
                        "timed_out": False,
                        "fields": {
                            "width": 3,
                            "height": 256016,
                            "bits_per_pixel": 24,
                            "bytes_per_line": 13,
                            "row_count": 268500991,
                            "payload_rows": 268500991,
                            "x_res": 150,
                            "y_res": 65535,
                        },
                    }
                ],
                "images": [],
            },
            handle,
        )


if __name__ == "__main__":
    unittest.main()
