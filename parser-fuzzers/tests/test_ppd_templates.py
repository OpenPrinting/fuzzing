from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.multitarget_runner import load_profiles
from parser_fuzzers.ppd_templates import make_ppd


class PPDTemplateTests(unittest.TestCase):
    def test_rastertopclx_template_keeps_filter_and_literal_payload(self) -> None:
        ppd = make_ppd("rastertopclx", 3)
        self.assertIn('*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"', ppd)
        self.assertIn("*cupsPCL EndJob", ppd)
        self.assertNotIn("%", ppd)

    def test_plain_rastertopclx_template_has_no_string_payload(self) -> None:
        ppd = make_ppd("rastertopclx_plain", 3)
        self.assertIn('*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"', ppd)
        self.assertNotIn("*cupsPCL EndJob", ppd)

    def test_string_sweep_template_uses_generic_values(self) -> None:
        ppd = make_ppd("rastertopclx_string_sweep", 5)
        self.assertIn("*cupsPCL EndJob", ppd)
        self.assertNotIn("%", ppd)

    def test_single_pagesize_template_keeps_required_page_region(self) -> None:
        ppd = make_ppd("rastertoescpx_single_pagesize", 0)
        self.assertIn('*cupsFilter: "application/vnd.cups-raster 0 rastertoescpx"', ppd)
        self.assertEqual(ppd.count("*PageSize Letter:"), 1)
        self.assertIn("*OpenUI *PageRegion", ppd)

    def test_parser_target_config_loads_all_profiles(self) -> None:
        profiles = load_profiles(ROOT / "configs" / "parser_targets.yaml")
        self.assertEqual(len(profiles), 4)
        self.assertEqual(profiles[0].id, "ppd_text_to_rastertopclx_smoke")

    def test_explore_target_config_loads_all_profiles(self) -> None:
        profiles = load_profiles(ROOT / "configs" / "parser_targets_explore.yaml")
        self.assertEqual(len(profiles), 4)
        self.assertEqual(profiles[0].id, "ppd_text_to_rastertopclx_explore")

    def test_coverage_template_adds_option_groups(self) -> None:
        ppd = make_ppd("pwg_resolution_coverage", 2)
        self.assertIn("*OpenUI *ColorModel", ppd)
        self.assertIn("*OpenUI *PrintQuality", ppd)
        self.assertIn("*OpenUI *MediaType", ppd)
        self.assertNotIn("65536x65536dpi", ppd)

    def test_coverage_target_config_loads_profiles(self) -> None:
        profiles = load_profiles(ROOT / "configs" / "parser_targets_coverage.yaml")
        self.assertEqual(len(profiles), 20)
        self.assertEqual(profiles[0].id, "cups_raster_to_rastertopclx_coverage")

    def test_pdf_and_image_coverage_templates_have_filter_lines(self) -> None:
        pdf = make_ppd("pdftoraster_coverage_options", 0)
        image = make_ppd("imagetoraster_coverage_options", 0)

        self.assertIn('*cupsFilter: "application/pdf 0 pdftoraster"', pdf)
        self.assertIn('*cupsFilter: "image/x-portable-anymap 0 imagetoraster"', image)
        self.assertIn("*OpenUI *ColorModel", pdf)

    def test_command_coverage_template_has_command_filter(self) -> None:
        ppd = make_ppd("commandtoescpx_coverage_options", 0)
        self.assertIn('*cupsFilter: "application/vnd.cups-command 0 commandtoescpx"', ppd)


if __name__ == "__main__":
    unittest.main()
