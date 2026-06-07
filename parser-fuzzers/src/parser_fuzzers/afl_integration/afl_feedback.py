from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AFLImportedCase:
    source: str
    source_path: str
    target_id: str
    case_id: int
    document_path: str
    crashed: bool
    sha256: str


@dataclass(frozen=True)
class AFLImportSummary:
    afl_instance_dir: str
    output_run_dir: str
    target_id: str
    queue_mode: str
    queue_imported: int
    crashes_imported: int
    duplicates_skipped: int
    imported: list[AFLImportedCase]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def import_afl_artifacts(
    *,
    afl_out: str | Path,
    target_id: str,
    output_run_dir: str | Path,
    extension: str = ".pwg",
    queue_limit: int = 512,
    crash_limit: int = 128,
    queue_mode: str = "new",
) -> AFLImportSummary:
    instance_dir = resolve_afl_instance_dir(afl_out)
    output_root = Path(output_run_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    normalized_queue_mode = _normalize_queue_mode(queue_mode)

    imported: list[AFLImportedCase] = []
    seen_hashes: set[str] = set()
    duplicates_skipped = 0
    next_case_id = 0

    queue_imported, next_case_id, duplicates = _import_group(
        source_files=_queue_files(instance_dir / "queue", normalized_queue_mode),
        output_root=output_root,
        target_id=target_id,
        extension=extension,
        source_label="afl-queue",
        crashed=False,
        limit=max(0, queue_limit),
        start_case_id=next_case_id,
        seen_hashes=seen_hashes,
        imported=imported,
    )
    duplicates_skipped += duplicates

    crashes_imported, next_case_id, duplicates = _import_group(
        source_files=_iter_afl_files(instance_dir / "crashes"),
        output_root=output_root,
        target_id=target_id,
        extension=extension,
        source_label="afl-crash",
        crashed=True,
        limit=max(0, crash_limit),
        start_case_id=next_case_id,
        seen_hashes=seen_hashes,
        imported=imported,
    )
    duplicates_skipped += duplicates

    summary = AFLImportSummary(
        afl_instance_dir=str(instance_dir),
        output_run_dir=str(output_root),
        target_id=target_id,
        queue_mode=normalized_queue_mode,
        queue_imported=queue_imported,
        crashes_imported=crashes_imported,
        duplicates_skipped=duplicates_skipped,
        imported=imported,
    )
    (output_root / "afl_import_manifest.json").write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_timeline(output_root, imported)
    return summary


def resolve_afl_instance_dir(path: str | Path) -> Path:
    root = Path(path)
    candidates = [
        root,
        root / "default",
        root / "out" / "default",
    ]
    for candidate in candidates:
        if (candidate / "queue").exists() or (candidate / "crashes").exists():
            return candidate
    raise FileNotFoundError(f"could not locate AFL++ queue/crashes under {root}")


def _import_group(
    *,
    source_files: Iterable[Path],
    output_root: Path,
    target_id: str,
    extension: str,
    source_label: str,
    crashed: bool,
    limit: int,
    start_case_id: int,
    seen_hashes: set[str],
    imported: list[AFLImportedCase],
) -> tuple[int, int, int]:
    count = 0
    duplicates = 0
    case_id = start_case_id
    if limit <= 0:
        return 0, case_id, 0
    for source_path in source_files:
        digest = _sha256_file(source_path)
        if digest in seen_hashes:
            duplicates += 1
            continue
        seen_hashes.add(digest)
        case_dir = _case_dir(output_root, target_id, case_id, crashed)
        case_dir.mkdir(parents=True, exist_ok=True)
        document_path = case_dir / f"document{extension}"
        shutil.copy2(source_path, document_path)
        record = AFLImportedCase(
            source=source_label,
            source_path=str(source_path),
            target_id=target_id,
            case_id=case_id,
            document_path=str(document_path),
            crashed=crashed,
            sha256=digest,
        )
        _write_meta(case_dir, record)
        imported.append(record)
        count += 1
        case_id += 1
        if count >= limit:
            break
    return count, case_id, duplicates


def _case_dir(output_root: Path, target_id: str, case_id: int, crashed: bool) -> Path:
    if crashed:
        return output_root / "quarantine" / "unique" / f"{target_id}-afl-case-{case_id:06d}"
    return output_root / "corpus" / "interesting" / target_id / f"case-{case_id:06d}"


def _write_meta(case_dir: Path, record: AFLImportedCase) -> None:
    meta = {
        "case_id": record.case_id,
        "crashed": record.crashed,
        "document_kind": "afl_import",
        "document_path": str(Path(record.document_path).resolve()),
        "oracle": "afl-crash" if record.crashed else "",
        "source": record.source,
        "source_path": record.source_path,
        "target_id": record.target_id,
        "timed_out": False,
        "work_dir": str(case_dir.resolve()),
    }
    (case_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_timeline(output_root: Path, imported: list[AFLImportedCase]) -> None:
    timeline = output_root / "timeline.jsonl"
    with timeline.open("w", encoding="utf-8") as handle:
        for item in imported:
            handle.write(
                json.dumps(
                    {
                        "case_id": item.case_id,
                        "crashed": item.crashed,
                        "document_path": item.document_path,
                        "oracle": "afl-crash" if item.crashed else "",
                        "source": item.source,
                        "target_id": item.target_id,
                        "timed_out": False,
                    },
                    sort_keys=True,
                )
                + "\n"
            )


def _iter_afl_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    files = []
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        if path.name.startswith(".") or path.name == "README.txt":
            continue
        files.append(path)
    return files


def _queue_files(root: Path, mode: str) -> list[Path]:
    if mode == "none":
        return []
    files = _iter_afl_files(root)
    if mode == "all":
        return files
    return [path for path in files if _is_afl_discovered_queue_entry(path)]


def _is_afl_discovered_queue_entry(path: Path) -> bool:
    name = path.name
    return "src:" in name or "sync:" in name or "splice" in name


def _normalize_queue_mode(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized in {"new", "discovered", "mutations", "mutated"}:
        return "new"
    if normalized in {"all", "everything"}:
        return "all"
    if normalized in {"none", "off", "0"}:
        return "none"
    raise ValueError(f"unknown AFL queue import mode: {mode}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
