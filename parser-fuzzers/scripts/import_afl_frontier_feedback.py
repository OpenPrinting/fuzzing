#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from parser_fuzzers.afl_feedback import import_afl_artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="import AFL++ queue/crashes into a runner-style feedback run")
    parser.add_argument("--afl-out", required=True, help="AFL++ output dir, instance dir, or campaign dir")
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output-run-dir", required=True)
    parser.add_argument("--extension", default=".pwg")
    parser.add_argument("--queue-limit", type=int, default=512)
    parser.add_argument("--crash-limit", type=int, default=128)
    parser.add_argument(
        "--queue-mode",
        choices=["new", "all", "none"],
        default="new",
        help="new imports AFL-discovered queue entries; all also imports original seeds",
    )
    args = parser.parse_args()

    summary = import_afl_artifacts(
        afl_out=args.afl_out,
        target_id=args.target_id,
        output_run_dir=args.output_run_dir,
        extension=args.extension,
        queue_limit=args.queue_limit,
        crash_limit=args.crash_limit,
        queue_mode=args.queue_mode,
    )
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
