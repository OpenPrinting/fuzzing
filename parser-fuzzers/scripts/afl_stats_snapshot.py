#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


FIELDS = [
    "run_time",
    "execs_done",
    "execs_per_sec",
    "corpus_count",
    "corpus_favored",
    "corpus_found",
    "saved_crashes",
    "saved_hangs",
    "cycles_done",
    "bitmap_cvg",
    "edges_found",
    "stability",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="print a compact AFL++ fuzzer_stats snapshot")
    parser.add_argument("output_dir")
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    stats_path = _stats_path(Path(args.output_dir))
    stats = _read_stats(stats_path) if stats_path is not None else _read_plot_data(Path(args.output_dir))
    if not stats:
        stats = _count_artifacts(Path(args.output_dir))
    prefix = f"{args.label} " if args.label else ""
    parts = [f"{field}={stats.get(field, 'n/a')}" for field in FIELDS if field in stats]
    for field in ("queue_files", "crash_files", "hang_files"):
        if field in stats and field not in FIELDS:
            parts.append(f"{field}={stats[field]}")
    print(prefix + " ".join(parts))
    return 0


def _stats_path(output_dir: Path) -> Path | None:
    candidates = [
        output_dir / "default" / "fuzzer_stats",
        output_dir / "fuzzer_stats",
    ]
    candidates.extend(sorted(output_dir.glob("*/fuzzer_stats")))
    for path in candidates:
        if path.exists():
            return path
    return None


def _read_stats(path: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def _read_plot_data(output_dir: Path) -> dict[str, str]:
    path = output_dir / "plot_data"
    if not path.exists():
        return {}
    lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    if len(lines) < 2:
        return _count_artifacts(output_dir)
    headers = [item.strip() for item in lines[0].lstrip("#").split(",")]
    values = [item.strip() for item in lines[-1].split(",")]
    row = dict(zip(headers, values))
    stats = _count_artifacts(output_dir)
    if "unix_time" in row:
        stats["run_time"] = row.get("run_time", row["unix_time"])
    if "total_execs" in row:
        stats["execs_done"] = row["total_execs"]
    if "exec_speed" in row:
        stats["execs_per_sec"] = row["exec_speed"]
    if "cycles_done" in row:
        stats["cycles_done"] = row["cycles_done"]
    if "saved_crashes" in row:
        stats["saved_crashes"] = row["saved_crashes"]
    if "saved_hangs" in row:
        stats["saved_hangs"] = row["saved_hangs"]
    return stats


def _count_artifacts(output_dir: Path) -> dict[str, str]:
    def count_files(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for item in path.iterdir() if item.is_file() and not item.name.startswith("README"))

    return {
        "queue_files": str(count_files(output_dir / "queue")),
        "crash_files": str(count_files(output_dir / "crashes")),
        "hang_files": str(count_files(output_dir / "hangs")),
    }


if __name__ == "__main__":
    raise SystemExit(main())
