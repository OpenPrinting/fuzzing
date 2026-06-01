from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smt_fuzzer.arithmetic_explorer import MOD32, iter_arithmetic_params


class ArithmeticExplorerTests(unittest.TestCase):
    def test_generator_produces_valid_cross_input_relations(self) -> None:
        params = [next(iter_arithmetic_params()) for _ in range(3)]
        for item in params:
            self.assertEqual(item.input_y_dpi % item.output_dpi, 0)
            self.assertGreaterEqual(item.bytes_per_line, 1)

    def test_generator_reaches_32bit_product_boundary(self) -> None:
        iterator = iter_arithmetic_params()
        boundary = None
        for _ in range(2000):
            item = next(iterator)
            if item.bytes_per_line * item.y_factor >= MOD32:
                boundary = item
                break
        self.assertIsNotNone(boundary)


if __name__ == "__main__":
    unittest.main()
