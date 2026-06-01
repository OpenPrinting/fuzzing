from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smt_fuzzer.hashing import sha256_bytes
from smt_fuzzer.models import BranchEvent
from smt_fuzzer.solver import MissingSolverError, condition_holds, read_event_value, solve_event


def make_event(data: bytes, op: str = "eq", rhs: int = 0x41) -> BranchEvent:
    return BranchEvent(
        target_id="unit",
        input_path="input.bin",
        input_sha256=sha256_bytes(data),
        offset=0,
        width=1,
        endianness="little",
        signed=False,
        op=op,
        rhs=rhs,
        description="unit test event",
    )


class SolverTests(unittest.TestCase):
    def test_bounded_fallback_solves_eq(self) -> None:
        data = b"\x00abc"
        event = make_event(data)
        result = solve_event(event, data, allow_fallback=True)
        self.assertEqual(result.status, "sat")
        self.assertEqual(result.patches[0].new_hex, "41")

    @unittest.skipUnless(importlib.util.find_spec("z3") is not None, "z3-solver is not installed")
    def test_z3_solves_eq(self) -> None:
        data = b"\x00abc"
        event = make_event(data)
        result = solve_event(event, data, allow_fallback=False)
        self.assertEqual(result.status, "sat")
        self.assertIn("z3", result.reason)

    def test_strict_solver_reports_missing_z3(self) -> None:
        if importlib.util.find_spec("z3") is not None:
            self.skipTest("z3-solver is installed")
        data = b"\x00abc"
        event = make_event(data)
        with self.assertRaises(MissingSolverError):
            solve_event(event, data, allow_fallback=False)

    def test_condition_holds_for_patched_value(self) -> None:
        data = b"\x00abc"
        event = make_event(data)
        result = solve_event(event, data, allow_fallback=True)
        patched = bytes.fromhex(result.patches[0].new_hex) + data[1:]
        self.assertTrue(condition_holds(event, read_event_value(event, patched)))


if __name__ == "__main__":
    unittest.main()
