#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from parser_fuzzers.afl_dynamic_bridge import augment_pwg_bundle_seed_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="augment PWG bundle AFL++ seeds with dynamic compare profile tokens")
    parser.add_argument("--seed-dir", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--limit", type=int, default=64)
    args = parser.parse_args()

    manifest = augment_pwg_bundle_seed_dir(
        args.seed_dir,
        args.profile,
        output_dir=args.output_dir or None,
        limit=args.limit,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
