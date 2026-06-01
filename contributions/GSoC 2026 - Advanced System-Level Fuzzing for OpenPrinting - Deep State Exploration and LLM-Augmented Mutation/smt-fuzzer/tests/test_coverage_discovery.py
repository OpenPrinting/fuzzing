from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from smt_fuzzer.multitarget_runner import TargetProfile, coverage_skip_reason, extract_case_features, run_case


class CoverageDiscoveryTests(unittest.TestCase):
    def test_skips_known_rastertoescpx_dotrowstep_zero_cases(self) -> None:
        profile = _profile("cups_raster_to_rastertoescpx_general", "cups_raster_general_sweep", "rastertoescpx_size_sweep")

        self.assertEqual(coverage_skip_reason(profile, 3), "known-rastertoescpx-dotrowstep-zero-fpe")
        self.assertEqual(coverage_skip_reason(profile, 15), "known-rastertoescpx-dotrowstep-zero-fpe")
        self.assertEqual(coverage_skip_reason(profile, 0), "")

    def test_skips_known_libppd_65536dpi_cases(self) -> None:
        profile = _profile("pwg_to_raster_general", "pwg_raster_general_sweep", "pwg_resolution_general")

        self.assertEqual(coverage_skip_reason(profile, 16), "known-libppd-65536dpi-fpe")
        self.assertEqual(coverage_skip_reason(profile, 33), "known-libppd-65536dpi-fpe")
        self.assertEqual(coverage_skip_reason(profile, 15), "")

    def test_extract_case_features_includes_document_header(self) -> None:
        profile = _profile("feature_test", "cups_raster_coverage_sweep", "rastertopclx_plain")
        with tempfile.TemporaryDirectory() as tmp:
            result = run_case(profile, 0, Path(tmp), timeout_sec=1, capture_stdout=False)
            features = extract_case_features(result)

        self.assertIn("target:feature_test", features)
        self.assertIn("doc-sync:3SaR", features)
        self.assertTrue(any(feature.startswith("doc-size:") for feature in features))

    def test_extract_case_features_recognizes_pdf_and_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdf_result = run_case(
                _profile("pdf_feature_test", "pdf_coverage_sweep", "pdftopdf_coverage_options"),
                0,
                Path(tmp) / "pdf",
                timeout_sec=1,
                capture_stdout=False,
            )
            png_result = run_case(
                _profile("png_feature_test", "image_coverage_sweep", "imagetoraster_coverage_options"),
                0,
                Path(tmp) / "png",
                timeout_sec=1,
                capture_stdout=False,
            )

            pdf_features = extract_case_features(pdf_result)
            png_features = extract_case_features(png_result)

        self.assertIn("doc-format:pdf", pdf_features)
        self.assertIn("doc-format:png", png_features)
        self.assertTrue(any(feature.startswith("doc-image-size:") for feature in png_features))


def _profile(target_id: str, document_kind: str, ppd_kind: str) -> TargetProfile:
    return TargetProfile(
        id=target_id,
        description="test",
        ppd_kind=ppd_kind,
        document_kind=document_kind,
        executor="direct_filter",
        input_mime="application/test",
        output_mime="",
        expected_filters=[],
        cases=1,
        oracle="crash_or_signal",
        filter_binary="/bin/true",
    )


if __name__ == "__main__":
    unittest.main()
