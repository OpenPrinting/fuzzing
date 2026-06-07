from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_fuzzers.source_constraints import mine_source_constraints, write_source_constraint_profile
from parser_fuzzers.structured_templates import pwg_structural_instance


class SourceConstraintTests(unittest.TestCase):
    def test_mines_field_and_option_hints_from_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample_filter.cxx"
            source.write_text(
                "\n".join(
                    [
                        'if (header.cupsBytesPerLine < row_bytes) return 1;',
                        'if (!strcmp(attr->name, "PageSize")) use_page();',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            profile = mine_source_constraints([source])

        self.assertGreaterEqual(profile["summary"]["records"], 2)
        self.assertGreater(profile["families"]["pwg"]["fields"].get("bytes_per_line", 0), 0)
        self.assertGreater(profile["ppd_options"].get("PageSize", 0), 0)

    def test_source_profile_biases_template_objective(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "source-hints.json"
            profile = {
                "schema_version": "source-constraint-hints-v1",
                "summary": {},
                "families": {"pwg": {"fields": {"bytes_per_line": 3}}},
                "ppd_options": {},
                "records": [],
                "template_bias": {
                    "pwg": {
                        "preferred_objectives": ["short_line"],
                        "preferred_feedback_variants": [1],
                    }
                },
            }
            write_source_constraint_profile(profile, profile_path)

            with patch.dict(
                "os.environ",
                {
                    "SMT_FUZZER_SOURCE_CONSTRAINTS": str(profile_path),
                    "SMT_FUZZER_SOURCE_CONSTRAINT_RATE": "1.0",
                },
                clear=False,
            ):
                instance = pwg_structural_instance(0)

        self.assertEqual(instance.objective, "short_line")
        self.assertIn(instance.solved_by, {"z3-source", "fallback"})


if __name__ == "__main__":
    unittest.main()
