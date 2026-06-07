#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="prepare AFL++ seeds from retained multitarget documents")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--extension", default=".pwg")
    parser.add_argument("--limit", type=int, default=256)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    interesting = run_dir / "corpus" / "interesting" / args.target_id
    if not interesting.exists():
        raise SystemExit(f"interesting corpus not found: {interesting}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for case_dir in sorted(interesting.glob("case-*")):
        if not case_dir.is_dir():
            continue
        documents = sorted(case_dir.glob(f"document*{args.extension}"))
        if not documents:
            continue
        source = documents[0]
        destination = output_dir / f"{case_dir.name}{args.extension}"
        shutil.copy2(source, destination)
        copied += 1
        if copied >= args.limit:
            break

    if copied == 0:
        raise SystemExit(f"no document*{args.extension} seeds found under {interesting}")
    print(f"prepared {copied} AFL++ seeds in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
