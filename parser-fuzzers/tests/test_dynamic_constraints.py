from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_fuzzers.dynamic_constraints import build_dynamic_compare_profile
from parser_fuzzers.multitarget_runner import TargetProfile, build_env_overrides
from parser_fuzzers.structured_templates import pwg_structural_instance


class DynamicConstraintTests(unittest.TestCase):
    def test_summarizes_compare_trace_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case_dir = run_dir / "target" / "case-0000"
            case_dir.mkdir(parents=True)
            (case_dir / "compare_trace.tsv").write_text(
                "\n".join(
                    [
                        "pid\tpc\top\tret\tlen\ta_hex\tb_hex\ta_ascii\tb_ascii",
                        "1\t0x1\tstrcmp\t0\t9\t\t\tPageSize\tPageSize",
                        "1\t0x2\tmemcmp\t1\t4\t\t\t2SaR\tRaS2",
                        "1\t0x3\tstrcmp\t1\t24\t\t\tapplication/vnd.cups-pwg.\ttext/plain",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            profile = build_dynamic_compare_profile(run_dir)

        self.assertEqual(profile["summary"]["trace_files"], 1)
        self.assertEqual(profile["summary"]["compare_records"], 3)
        self.assertEqual(profile["ppd_options"]["PageSize"], 1)
        self.assertEqual(profile["magic_tokens"]["2SaR"], 1)
        self.assertEqual(profile["tokens"]["application/vnd.cups-pwg"], 1)

    def test_runner_env_enables_dynamic_compare_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_lib = root / "libtrace.so"
            trace_lib.write_bytes(b"placeholder")
            case_dir = root / "case-0000"
            case_dir.mkdir()
            profile = TargetProfile(
                id="pwg_to_pdf",
                description="",
                ppd_kind="pwgtopdf_coverage_options",
                document_kind="pwg_raster_structural_sweep",
                executor="direct_filter",
                input_mime="application/vnd.cups-pwg",
                output_mime="",
                expected_filters=["pwgtopdf"],
                cases=1,
                oracle="crash_or_signal",
                filter_binary="/data/pre-gsoc/cups-filters/pwgtopdf",
            )

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_DYNAMIC_COMPARE_TRACE_LIB": str(trace_lib),
                    "SMT_FUZZER_COMPARE_TRACE_LIMIT": "7",
                },
                clear=False,
            ):
                env = build_env_overrides(profile, root / "candidate.ppd", case_dir)

        self.assertEqual(env["SMT_FUZZER_COMPARE_TRACE"], str(case_dir / "compare_trace.tsv"))
        self.assertEqual(env["SMT_FUZZER_COMPARE_TRACE_LIMIT"], "7")
        self.assertIn(str(trace_lib), env["LD_PRELOAD"])
        self.assertIn("verify_asan_link_order=0", env["ASAN_OPTIONS"])

    def test_runner_env_can_sample_dynamic_compare_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace_lib = root / "libtrace.so"
            trace_lib.write_bytes(b"placeholder")
            traced_case = root / "case-0002"
            skipped_case = root / "case-0003"
            max_skipped_case = root / "case-0006"
            traced_case.mkdir()
            skipped_case.mkdir()
            max_skipped_case.mkdir()
            profile = TargetProfile(
                id="pwg_to_pdf",
                description="",
                ppd_kind="pwgtopdf_coverage_options",
                document_kind="pwg_raster_structural_sweep",
                executor="direct_filter",
                input_mime="application/vnd.cups-pwg",
                output_mime="",
                expected_filters=["pwgtopdf"],
                cases=1,
                oracle="crash_or_signal",
                filter_binary="/data/pre-gsoc/cups-filters/pwgtopdf",
            )

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_DYNAMIC_COMPARE_TRACE_LIB": str(trace_lib),
                    "SMT_FUZZER_DYNAMIC_COMPARE_TRACE_EVERY": "2",
                    "SMT_FUZZER_DYNAMIC_COMPARE_TRACE_MAX_CASES": "5",
                },
                clear=False,
            ):
                traced = build_env_overrides(profile, root / "candidate.ppd", traced_case)
                skipped = build_env_overrides(profile, root / "candidate.ppd", skipped_case)
                max_skipped = build_env_overrides(profile, root / "candidate.ppd", max_skipped_case)

        self.assertIn("SMT_FUZZER_COMPARE_TRACE", traced)
        self.assertNotIn("SMT_FUZZER_COMPARE_TRACE", skipped)
        self.assertNotIn("SMT_FUZZER_COMPARE_TRACE", max_skipped)

    def test_dynamic_profile_can_bias_template_objective(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "dynamic.json"
            profile_path.write_text(
                """
{
  "schema_version": "dynamic-compare-hints-v1",
  "summary": {"compare_records": 4},
  "tokens": {"cupsBytesPerLine": 4},
  "ppd_options": {"cupsBytesPerLine": 4},
  "magic_tokens": {},
  "records": []
}
""".lstrip(),
                encoding="utf-8",
            )

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_DYNAMIC_CONSTRAINTS": str(profile_path),
                    "SMT_FUZZER_SOURCE_CONSTRAINT_RATE": "1.0",
                },
                clear=False,
            ):
                instance = pwg_structural_instance(1)

        self.assertEqual(instance.objective, "short_line")
        self.assertIn(instance.solved_by, {"z3-source", "fallback"})


if __name__ == "__main__":
    unittest.main()
