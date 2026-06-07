#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from parser_fuzzers.afl_dynamic_bridge import write_dynamic_afl_dictionary


def main() -> int:
    parser = argparse.ArgumentParser(description="convert dynamic compare profile tokens into an AFL++ dictionary")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--base-dictionary", default="")
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args()

    manifest = write_dynamic_afl_dictionary(
        args.profile,
        args.output,
        base_dictionary=args.base_dictionary or None,
        max_tokens=args.max_tokens,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
