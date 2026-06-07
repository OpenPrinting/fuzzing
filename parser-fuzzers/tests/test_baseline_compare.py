from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.baseline_compare import (
    build_comparison_payload,
    inspect_oss_fuzz_cups_filters,
    render_comparison_markdown,
)


class BaselineCompareTests(unittest.TestCase):
    def test_inspect_oss_fuzz_project_reads_dockerfile_build_script_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "projects" / "cups-filters"
            project.mkdir(parents=True)
            (project / "project.yaml").write_text("language: c++\n", encoding="utf-8")
            (project / "Dockerfile").write_text(
                "FROM gcr.io/oss-fuzz-base/base-builder\n"
                "RUN cp $SRC/fuzzing/projects/cups-filters/oss_fuzz_build.sh $SRC/build.sh\n",
                encoding="utf-8",
            )
            (project / "run_tests.sh").write_text("make check\n", encoding="utf-8")

            status = inspect_oss_fuzz_cups_filters(tmp)

        self.assertTrue(status.project_exists)
        self.assertFalse(status.has_project_build_sh)
        self.assertIn("oss_fuzz_build.sh", status.build_sh_source)
        self.assertEqual(len(status.helper_commands), 4)

    def test_build_comparison_payload_computes_selected_delta(self) -> None:
        baseline = {
            "run_dir": "base",
            "run": {
                "elapsed_sec": 60,
                "cases": 10,
                "retained_cases": 4,
                "coverage_features": 20,
                "crashes": 2,
                "unique_crashes": 1,
            },
            "derived": {
                "features_per_min": 20.0,
                "retained_density": 0.4,
                "crash_density": 0.2,
            },
            "llvm_cov": {
                "totals": {
                    "functions": {"covered": 5, "percent": 10.0},
                    "lines": {"covered": 50, "percent": 12.5},
                    "branches": {"covered": 7, "percent": 3.5},
                }
            },
        }
        optimized = {
            "run_dir": "opt",
            "run": {
                "elapsed_sec": 60,
                "cases": 12,
                "retained_cases": 8,
                "coverage_features": 36,
                "crashes": 1,
                "unique_crashes": 1,
            },
            "derived": {
                "features_per_min": 36.0,
                "retained_density": 0.666667,
                "crash_density": 0.083333,
            },
            "llvm_cov": {
                "totals": {
                    "functions": {"covered": 8, "percent": 16.0},
                    "lines": {"covered": 70, "percent": 17.5},
                    "branches": {"covered": 9, "percent": 4.5},
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            status = inspect_oss_fuzz_cups_filters(tmp)

        payload = build_comparison_payload(
            comparison_id="cmp",
            config_path="config.yaml",
            baseline=baseline,
            optimized=optimized,
            oss_fuzz_status=status,
        )
        markdown = render_comparison_markdown(payload)

        self.assertEqual(payload["metrics"]["delta"]["coverage_features"], 16.0)
        self.assertEqual(payload["metrics"]["delta"]["llvm_functions_percent"], 6.0)
        self.assertIn("Local Fair Comparison", markdown)
        self.assertIn("features/min", markdown)


if __name__ == "__main__":
    unittest.main()
