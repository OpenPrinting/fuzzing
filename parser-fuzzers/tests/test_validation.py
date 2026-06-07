from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.validation import validate_all, validate_bug_metadata, validate_bug_suite


class ValidationTests(unittest.TestCase):
    def test_project_metadata_validates(self) -> None:
        issues = validate_all(ROOT / "bugs", ROOT / "configs", require_local_artifacts=False)
        errors = [issue for issue in issues if issue.level == "error"]
        self.assertEqual(errors, [])

    def test_public_bug_suite_is_optional(self) -> None:
        issues = validate_bug_suite(ROOT / "bugs", require_local_artifacts=False)
        self.assertEqual([issue for issue in issues if issue.level == "error"], [])
        self.assertEqual(list((ROOT / "bugs").glob("*/meta.yaml")), [])

    def test_clone_only_validation_demotes_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            meta = Path(tmp) / "meta.yaml"
            meta.write_text(
                "\n".join(
                    [
                        "id: X1",
                        "title: clone-only metadata",
                        "component: cups-filters",
                        "bug_type: CWE-000",
                        "target_component: parser",
                        "poc_path: /private/local/reproducer.bin",
                        "known_poc_allowed_in_seed: false",
                        "timeout_sec: 3",
                        "memory_mb: 128",
                        "report_path: /definitely/missing/report.md",
                        "oracle:",
                        "  reached: {}",
                        "  triggered: {}",
                        "  detected: {}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            clone_issues = validate_bug_metadata(meta, require_local_artifacts=False)
            strict_issues = validate_bug_metadata(meta, require_local_artifacts=True)
        self.assertEqual([issue for issue in clone_issues if issue.level == "error"], [])
        self.assertEqual(sum(1 for issue in clone_issues if issue.level == "warning"), 2)
        self.assertEqual(sum(1 for issue in strict_issues if issue.level == "error"), 2)


if __name__ == "__main__":
    unittest.main()
