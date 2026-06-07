from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser_fuzzers.validation import load_yaml


class SeedPolicyTests(unittest.TestCase):
    def test_private_reproducers_are_not_allowed_in_seed(self) -> None:
        for meta_path in sorted((ROOT / "bugs").glob("*/meta.yaml")):
            meta = load_yaml(meta_path)
            self.assertIs(meta["known_poc_allowed_in_seed"], False, meta_path)

    def test_public_seeds_do_not_copy_private_reproducer_names(self) -> None:
        seed_names = {path.name for path in (ROOT / "seeds" / "public").glob("*") if path.is_file()}
        private_markers = ("poc", "repro", "crash", "asan", "issue")
        self.assertFalse(
            [name for name in seed_names if any(marker in name.lower() for marker in private_markers)]
        )


if __name__ == "__main__":
    unittest.main()
