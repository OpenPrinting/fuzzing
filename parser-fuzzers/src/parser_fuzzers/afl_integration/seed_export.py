from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ExportedSeed:
    source_case_dir: str
    source_path: str
    target_id: str
    output_path: str


@dataclass(frozen=True)
class SeedExportSummary:
    run_dir: str
    output_dir: str
    targets: list[str]
    extensions: list[str]
    exported: int
    exported_by_target: dict[str, int] = field(default_factory=dict)
    seeds: list[ExportedSeed] = field(default_factory=list)
    manifest_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def export_template_seeds(
    *,
    run_dir: str | Path,
    output_dir: str | Path,
    target_ids: Iterable[str] | None = None,
    extensions: Iterable[str] | None = None,
    limit: int = 0,
    include_crashes: bool = False,
    include_ppd: bool = False,
    manifest_name: str = "seed_export_manifest.json",
) -> SeedExportSummary:
    root = Path(run_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target_filter = {item for item in (target_ids or []) if item}
    extension_filter = {_normalize_extension(item) for item in (extensions or []) if item}
    exported: list[ExportedSeed] = []
    by_target: dict[str, int] = {}

    for target_id, case_dir in _iter_case_dirs(root, target_filter, include_crashes=include_crashes):
        for source in _iter_seed_files(case_dir, extension_filter, include_ppd=include_ppd):
            if limit > 0 and len(exported) >= limit:
                break
            suffix = source.suffix or ".bin"
            destination = out / f"{target_id}-{case_dir.name}-{len(exported):06d}{suffix}"
            shutil.copy2(source, destination)
            exported.append(
                ExportedSeed(
                    source_case_dir=str(case_dir),
                    source_path=str(source),
                    target_id=target_id,
                    output_path=str(destination),
                )
            )
            by_target[target_id] = by_target.get(target_id, 0) + 1
        if limit > 0 and len(exported) >= limit:
            break

    manifest_path = _manifest_path_for_seed_dir(out, manifest_name)
    summary = SeedExportSummary(
        run_dir=str(root),
        output_dir=str(out),
        targets=sorted(target_filter),
        extensions=sorted(extension_filter),
        exported=len(exported),
        exported_by_target=dict(sorted(by_target.items())),
        seeds=exported,
        manifest_path=str(manifest_path),
    )
    manifest_path.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def _iter_case_dirs(
    root: Path,
    target_filter: set[str],
    *,
    include_crashes: bool,
) -> Iterable[tuple[str, Path]]:
    interesting_root = root / "corpus" / "interesting"
    if interesting_root.exists():
        for target_dir in sorted(interesting_root.iterdir()):
            if not target_dir.is_dir():
                continue
            target_id = target_dir.name
            if target_filter and target_id not in target_filter:
                continue
            for case_dir in sorted(target_dir.glob("case-*")):
                if case_dir.is_dir():
                    yield target_id, case_dir

    if include_crashes:
        quarantine_root = root / "quarantine" / "unique"
        if quarantine_root.exists():
            for case_dir in sorted(quarantine_root.iterdir()):
                if not case_dir.is_dir():
                    continue
                target_id = _target_from_quarantine_case(case_dir.name)
                if target_filter and target_id not in target_filter:
                    continue
                yield target_id, case_dir


def _iter_seed_files(case_dir: Path, extension_filter: set[str], *, include_ppd: bool) -> Iterable[Path]:
    patterns = ["document*"]
    if include_ppd:
        patterns.append("candidate.ppd")
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(case_dir.glob(pattern)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            if extension_filter and _normalize_extension(path.suffix or ".bin") not in extension_filter:
                continue
            yield path


def _normalize_extension(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    return value if value.startswith(".") else f".{value}"


def _manifest_path_for_seed_dir(seed_dir: Path, manifest_name: str) -> Path:
    requested = Path(manifest_name)
    if requested.is_absolute():
        return requested
    if requested.parent != Path("."):
        return seed_dir / requested
    return seed_dir.parent / f"{seed_dir.name}-{manifest_name}"


def _target_from_quarantine_case(name: str) -> str:
    marker = "-case-"
    if marker in name:
        return name.split(marker, 1)[0]
    marker = "-afl-case-"
    if marker in name:
        return name.split(marker, 1)[0]
    return name
