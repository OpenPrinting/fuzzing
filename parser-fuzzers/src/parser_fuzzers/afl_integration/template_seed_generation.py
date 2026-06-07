from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from parser_fuzzers.document_harness import make_document


@dataclass(frozen=True)
class GeneratedTemplateSeed:
    case_index: int
    document_kind: str
    extension: str
    mime: str
    description: str
    output_path: str
    size: int


@dataclass(frozen=True)
class TemplateSeedGenerationSummary:
    document_kind: str
    target_id: str
    output_dir: str
    count: int
    start_index: int
    extension_filter: list[str]
    generated: int
    seeds: list[GeneratedTemplateSeed] = field(default_factory=list)
    manifest_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def generate_template_seeds(
    *,
    document_kind: str,
    output_dir: str | Path,
    count: int,
    target_id: str = "",
    start_index: int = 0,
    extensions: list[str] | None = None,
    manifest_name: str = "template_seed_manifest.json",
) -> TemplateSeedGenerationSummary:
    if count <= 0:
        raise ValueError("count must be positive")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    extension_filter = sorted({_normalize_extension(item) for item in (extensions or []) if item})
    generated: list[GeneratedTemplateSeed] = []
    case_index = max(0, start_index)
    max_attempts = count * 32
    attempts = 0

    while len(generated) < count and attempts < max_attempts:
        attempts += 1
        document = make_document(document_kind, case_index, target_id=target_id)
        extension = _normalize_extension(document.extension or ".bin")
        if not extension_filter or extension in extension_filter:
            output_path = out / f"{document_kind}-{case_index:06d}{extension}"
            output_path.write_bytes(document.data)
            generated.append(
                GeneratedTemplateSeed(
                    case_index=case_index,
                    document_kind=document.kind,
                    extension=extension,
                    mime=document.mime,
                    description=document.description,
                    output_path=str(output_path),
                    size=len(document.data),
                )
            )
        case_index += 1

    manifest_path = _manifest_path_for_seed_dir(out, manifest_name)
    summary = TemplateSeedGenerationSummary(
        document_kind=document_kind,
        target_id=target_id,
        output_dir=str(out),
        count=count,
        start_index=max(0, start_index),
        extension_filter=extension_filter,
        generated=len(generated),
        seeds=generated,
        manifest_path=str(manifest_path),
    )
    manifest_path.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


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
