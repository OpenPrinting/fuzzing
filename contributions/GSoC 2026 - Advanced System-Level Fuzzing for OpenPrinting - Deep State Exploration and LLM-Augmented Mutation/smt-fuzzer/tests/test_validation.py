from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smt_fuzzer.validation import validate_all


class ValidationTests(unittest.TestCase):
    def test_project_configs_validate(self) -> None:
        issues = validate_all(ROOT / "configs")
        errors = [issue for issue in issues if issue.level == "error"]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
