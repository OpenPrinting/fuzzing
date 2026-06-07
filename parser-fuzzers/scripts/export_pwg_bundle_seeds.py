#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


MAGIC = b"SMT_PWG_BUNDLE_V1\n"
PPD_MARK = b"--SMT-PPD--\n"
OPTIONS_MARK = b"--SMT-OPTIONS--\n"
DOCUMENT_MARK = b"--SMT-DOCUMENT--\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="export AFL++ PWG bundle seeds with PPD, job options, and document")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--limit", type=int, default=512)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    interesting = run_dir / "corpus" / "interesting" / args.target_id
    if not interesting.exists():
        raise SystemExit(f"interesting corpus not found: {interesting}")

    output_dir = Path(args.output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    exported = []
    for case_dir in sorted(interesting.glob("case-*")):
        if args.limit > 0 and len(exported) >= args.limit:
            break
        ppd = case_dir / "candidate.ppd"
        doc = case_dir / "document.pwg"
        if not ppd.exists() or not doc.exists():
            continue
        options = _job_options(case_dir)
        out = output_dir / f"{args.target_id}-{case_dir.name}-{len(exported):06d}.pwg-bundle"
        out.write_bytes(
            MAGIC
            + PPD_MARK
            + ppd.read_bytes()
            + b"\n"
            + OPTIONS_MARK
            + options.encode("utf-8", errors="replace")
            + b"\n"
            + DOCUMENT_MARK
            + doc.read_bytes()
        )
        exported.append(
            {
                "source_case_dir": str(case_dir),
                "source_ppd": str(ppd),
                "source_document": str(doc),
                "job_options": options,
                "output_path": str(out),
            }
        )

    if not exported:
        raise SystemExit(f"no bundle seeds exported from {interesting}")

    manifest = {
        "run_dir": str(run_dir),
        "target_id": args.target_id,
        "output_dir": str(output_dir),
        "exported": len(exported),
        "format": "SMT_PWG_BUNDLE_V1",
        "seeds": exported,
    }
    (output_dir / "bundle_seed_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _job_options(case_dir: Path) -> str:
    meta = case_dir / "meta.json"
    if not meta.exists():
        return ""
    try:
        payload = json.loads(meta.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ""
    return str(payload.get("job_options") or "")


if __name__ == "__main__":
    raise SystemExit(main())
