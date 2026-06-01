from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from smt_fuzzer.hashing import sha256_bytes, sha256_file
from smt_fuzzer.models import BranchEvent, Patch, SolverResult
from smt_fuzzer.patcher import apply_patches, apply_solver_result


class PatcherTests(unittest.TestCase):
    def test_apply_patches_rewrites_expected_bytes(self) -> None:
        patch = Patch(offset=1, old_hex="00", new_hex="41", width=1)
        self.assertEqual(apply_patches(b"x\x00z", [patch]), b"xAz")

    def test_apply_patches_rejects_old_byte_mismatch(self) -> None:
        patch = Patch(offset=1, old_hex="00", new_hex="41", width=1)
        with self.assertRaises(ValueError):
            apply_patches(b"xyz", [patch])

    def test_apply_solver_result_writes_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.bin"
            input_path.write_bytes(b"\x00abc")
            event = BranchEvent(
                target_id="unit",
                input_path=str(input_path),
                input_sha256=sha256_file(input_path),
                offset=0,
                width=1,
                endianness="little",
                signed=False,
                op="eq",
                rhs=0x41,
                description="unit test",
            )
            result = SolverResult(
                status="sat",
                solver_ms=1.0,
                patches=[Patch(offset=0, old_hex="00", new_hex="41", width=1)],
                reason="unit",
                event=event,
            )
            output = apply_solver_result(result, input_path, root / "out")
            self.assertTrue(output.exists())
            self.assertEqual(output.read_bytes(), b"Aabc")
            self.assertNotEqual(sha256_bytes(output.read_bytes()), event.input_sha256)


if __name__ == "__main__":
    unittest.main()
