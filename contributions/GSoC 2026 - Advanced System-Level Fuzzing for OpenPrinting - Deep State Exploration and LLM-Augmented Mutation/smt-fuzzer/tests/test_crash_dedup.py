from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from smt_fuzzer.crash_dedup import dedup_run


class CrashDedupTests(unittest.TestCase):
    def test_deduplicates_asan_summary_and_excludes_infra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr_a = root / "a.stderr"
            stderr_b = root / "b.stderr"
            stderr_infra = root / "infra.stderr"
            stderr_a.write_text(
                "==11==ERROR: AddressSanitizer: FPE on unknown address 0x111\n"
                "SUMMARY: AddressSanitizer: FPE filter/rastertoescpx.c:1694 in ProcessLine\n",
                encoding="utf-8",
            )
            stderr_b.write_text(
                "==22==ERROR: AddressSanitizer: FPE on unknown address 0x222\n"
                "SUMMARY: AddressSanitizer: FPE filter/rastertoescpx.c:1694 in ProcessLine\n",
                encoding="utf-8",
            )
            stderr_infra.write_text(
                "==33==ASan runtime does not come first in initial library list\n",
                encoding="utf-8",
            )
            records = [
                _record(0, stderr_a, "case-a"),
                _record(1, stderr_b, "case-b"),
                _record(2, stderr_infra, "case-infra"),
            ]
            with (root / "timeline.jsonl").open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")

            summary = dedup_run(root)

            self.assertEqual(summary.crash_records, 3)
            self.assertEqual(summary.infra_excluded_records, 1)
            self.assertEqual(summary.unique_crashes, 1)
            self.assertEqual(summary.clusters[0].count, 2)


def _record(case_id: int, stderr_path: Path, work_dir: str) -> dict[str, object]:
    return {
        "target_id": "cups_raster_to_rastertoescpx_general",
        "case_id": case_id,
        "work_dir": work_dir,
        "command_line": "target @@",
        "stderr_path": str(stderr_path),
        "crashed": True,
        "timed_out": False,
        "oracle": "stderr crash/sanitizer",
        "returncode": 86,
    }


if __name__ == "__main__":
    unittest.main()
