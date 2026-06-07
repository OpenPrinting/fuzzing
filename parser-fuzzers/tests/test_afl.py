from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.afl import afl_build_env, build_afl_plan


class AFLTests(unittest.TestCase):
    def test_afl_build_env_uses_afl_wrappers(self) -> None:
        env = afl_build_env(ROOT / "configs")
        self.assertEqual(env["CC"], "afl-clang-fast")
        self.assertEqual(env["CXX"], "afl-clang-fast++")
        self.assertIn("address", env["CFLAGS"])

    def test_dictionary_config_materializes_merged_dictionary(self) -> None:
        plan = build_afl_plan(
            ROOT,
            "configs",
            "ppd_ipp_parser",
            "A1",
            "harnesses/bin/ppd_ipp_parser",
        )
        self.assertIsNotNone(plan.dictionary)
        dictionary = Path(plan.dictionary or "")
        self.assertTrue(dictionary.exists())
        self.assertIn("-x", plan.argv)
        self.assertIn('"*PPD-Adobe:"', dictionary.read_text(encoding="utf-8"))
        self.assertFalse(any("/private/local/reproducer" in arg for arg in plan.argv))

    def test_cmplog_config_adds_cmplog_binary(self) -> None:
        plan = build_afl_plan(
            ROOT,
            "configs",
            "ppd_ipp_parser",
            "A2",
            "harnesses/bin/ppd_ipp_parser",
        )
        self.assertIn("-c", plan.argv)
        self.assertEqual(plan.cmplog_binary, "harnesses/bin/ppd_ipp_parser.cmplog")
        self.assertTrue(any("CmpLog config requested" in warning for warning in plan.warnings))

    def test_smt_config_imports_smt_corpus(self) -> None:
        smt_dir = ROOT / "work" / "corpus" / "smt"
        smt_dir.mkdir(parents=True, exist_ok=True)
        (smt_dir / "unit-smt-input.bin").write_bytes(b"SMT")
        plan = build_afl_plan(
            ROOT,
            "configs",
            "image_options_parser",
            "A4",
            "harnesses/bin/image_options_parser",
        )
        input_dir = Path(plan.input_dir)
        self.assertTrue((input_dir / "smt-unit-smt-input.bin").exists())
        self.assertIsNotNone(plan.dictionary)

    def test_standard_afl_plan_accepts_template_seed_directory(self) -> None:
        seed_dir = ROOT / "seeds" / "public"
        output_dir = ROOT / "work" / "unit-afl-output"
        plan = build_afl_plan(
            ROOT,
            "configs",
            "template_probe_pwg",
            "A1",
            "work/afl/bin/template_probe",
            input_dir=seed_dir,
            output_dir=output_dir,
            duration_sec=123,
            timeout_ms=777,
            memory_mb=256,
        )
        self.assertEqual(plan.input_dir, str(seed_dir))
        self.assertEqual(plan.output_dir, str(output_dir))
        self.assertIn("-V", plan.argv)
        self.assertIn("123", plan.argv)
        self.assertIn("-t", plan.argv)
        self.assertIn("777", plan.argv)
        self.assertNotIn("-n", plan.argv)
        self.assertEqual(plan.argv[-2:], ["work/afl/bin/template_probe", "@@"])


if __name__ == "__main__":
    unittest.main()
