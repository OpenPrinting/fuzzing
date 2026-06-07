#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import tarfile
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="archive AFL++ crash/hang artifacts and optionally prune raw files")
    parser.add_argument("--run-dir", required=True, help="AFL++ campaign directory")
    parser.add_argument("--output-dir", default="findings", help="directory for the archive")
    parser.add_argument("--label", default="", help="archive label; defaults to run-dir name")
    parser.add_argument("--delete-after-archive", action="store_true", help="remove raw crash/hang files after archive succeeds")
    parser.add_argument("--include-queue", action="store_true", help="also include AFL++ queue files")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        raise SystemExit(f"run dir not found: {run_dir}")

    label = args.label or run_dir.name
    stamp = time.strftime("%Y%m%d-%H%M%S")
    archive_root = Path(args.output_dir)
    archive_root.mkdir(parents=True, exist_ok=True)
    staging = archive_root / f"{label}-afl-artifacts-{stamp}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    copied: list[dict[str, str | int]] = []
    for src in _artifact_paths(run_dir, include_queue=args.include_queue):
        rel = src.relative_to(run_dir)
        dst = staging / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            size = _dir_size(src)
            kind = "dir"
        else:
            shutil.copy2(src, dst)
            size = src.stat().st_size
            kind = "file"
        copied.append({"kind": kind, "source": str(src), "archive_path": str(dst), "bytes": size})

    manifest = {
        "run_dir": str(run_dir),
        "staging_dir": str(staging),
        "include_queue": args.include_queue,
        "delete_after_archive": args.delete_after_archive,
        "copied": copied,
        "crash_files": len(_raw_files(run_dir, "crashes")),
        "hang_files": len(_raw_files(run_dir, "hangs")),
        "run_dir_bytes_before": _dir_size(run_dir),
    }
    (staging / "archive_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    archive_path = staging.with_suffix(".tar.gz")
    if archive_path.exists():
        archive_path.unlink()
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(staging, arcname=staging.name)

    deleted = []
    if args.delete_after_archive:
        for subdir in ("crashes", "hangs"):
            for path in _raw_files(run_dir, subdir):
                if path.name == "README.txt":
                    continue
                deleted.append({"path": str(path), "bytes": path.stat().st_size})
                path.unlink()
        manifest["deleted"] = deleted
        manifest["run_dir_bytes_after"] = _dir_size(run_dir)
        (staging / "archive_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(staging, arcname=staging.name)

    print(
        json.dumps(
            {
                "archive": str(archive_path),
                "staging_dir": str(staging),
                "copied_items": len(copied),
                "deleted_files": len(deleted),
                "run_dir_bytes_before": manifest["run_dir_bytes_before"],
                "run_dir_bytes_after": manifest.get("run_dir_bytes_after", manifest["run_dir_bytes_before"]),
                "archive_bytes": archive_path.stat().st_size,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _artifact_paths(run_dir: Path, *, include_queue: bool) -> list[Path]:
    paths: list[Path] = []
    for relative in [
        "standard-metrics.json",
        "manifest.json",
        "fuzzer_stats",
        "afl.log",
        "dynamic-pwg-bundle.dict",
        "dynamic-dict-export.json",
        "dynamic-seed-augment.json",
        "bundle-seed-export.json",
        "bundle_seed_manifest.json",
        "fallback.ppd",
    ]:
        path = run_dir / relative
        if path.exists():
            paths.append(path)
    for pattern in ["out/*/fuzzer_stats", "out/*/crashes", "out/*/hangs"]:
        paths.extend(sorted(run_dir.glob(pattern)))
    if include_queue:
        paths.extend(sorted(run_dir.glob("out/*/queue")))
    return _dedupe(paths)


def _raw_files(run_dir: Path, subdir: str) -> list[Path]:
    files: list[Path] = []
    for root in run_dir.glob(f"out/*/{subdir}"):
        files.extend(path for path in root.iterdir() if path.is_file())
    return sorted(files)


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def _dir_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


if __name__ == "__main__":
    raise SystemExit(main())
