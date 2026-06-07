from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.crash_dedup import dedup_run


class CrashDedupTests(unittest.TestCase):
    def test_deduplicates_asan_summary_and_excludes_infra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr_a = root / "a.stderr"
            stderr_b = root / "b.stderr"
            stderr_infra = root / "infra.stderr"
            stderr_a.write_text(
                "==11==ERROR: AddressSanitizer: FPE on unknown address 0x111\n"
                "SUMMARY: AddressSanitizer: FPE example/raster_filter.c:42 in process_line\n",
                encoding="utf-8",
            )
            stderr_b.write_text(
                "==22==ERROR: AddressSanitizer: FPE on unknown address 0x222\n"
                "SUMMARY: AddressSanitizer: FPE example/raster_filter.c:42 in process_line\n",
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

    def test_generic_libc_summary_uses_first_project_frame_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr_path = root / "pdftoraster.stderr"
            stderr_path.write_text(
                "SUMMARY: AddressSanitizer: SEGV ../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:328 in __memset_avx2_unaligned_erms\n"
                "    #0 0x7f in __memset_avx2_unaligned_erms ../sysdeps/x86_64/multiarch/memset-vec-unaligned-erms.S:328\n"
                "    #1 0x7f in memset /usr/include/x86_64-linux-gnu/bits/string_fortified.h:59\n"
                "    #2 0x7f in write_page_image cupsfilters/pdftoraster.c:2013\n",
                encoding="utf-8",
            )
            with (root / "timeline.jsonl").open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(_record(0, stderr_path, "case-pdf")) + "\n")

            summary = dedup_run(root)

            self.assertEqual(summary.unique_crashes, 1)
            self.assertIn("write_page_image cupsfilters/pdftoraster.c:2013", summary.clusters[0].signature)


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
