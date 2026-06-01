from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

class SeedPolicyTests(unittest.TestCase):
    def test_public_seeds_are_weak_generic_inputs(self) -> None:
        seed_files = sorted(path for path in (ROOT / "seeds" / "public").glob("*") if path.is_file())
        self.assertTrue(seed_files)
        self.assertTrue(all(path.suffix in {"", ".md", ".txt"} for path in seed_files))


if __name__ == "__main__":
    unittest.main()
