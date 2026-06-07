from __future__ import annotations

import json
import struct
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


HEADER_SIZE = 1796
SYNC_CUPS_RASTER_V3 = b"3SaR"
SYNC_PWG_RASTER = b"2SaR"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

OFF_HW_RESOLUTION = 276
OFF_CUPS_WIDTH = 372
OFF_CUPS_HEIGHT = 376
OFF_CUPS_BITS_PER_PIXEL = 388
OFF_CUPS_BYTES_PER_LINE = 392
OFF_CUPS_COLOR_ORDER = 396
OFF_CUPS_COLOR_SPACE = 400
OFF_CUPS_COMPRESSION = 404
OFF_CUPS_ROW_COUNT = 408
OFF_CUPS_NUM_COLORS = 420


@dataclass(frozen=True)
class FeedbackSeed:
    kind: str
    source: str
    target_id: str
    case_id: int
    document_path: str
    crashed: bool
    timed_out: bool
    fields: dict[str, int]


@dataclass(frozen=True)
class FeedbackProfile:
    source_run_dir: str
    cups: list[FeedbackSeed]
    pwg: list[FeedbackSeed]
    images: list[FeedbackSeed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_run_dir": self.source_run_dir,
            "cups": [asdict(seed) for seed in self.cups],
            "pwg": [asdict(seed) for seed in self.pwg],
            "images": [asdict(seed) for seed in self.images],
        }


@dataclass(frozen=True)
class _FeedbackCandidate:
    seed: FeedbackSeed
    score: float
    diversity_key: tuple[Any, ...]


def build_feedback_profile(
    run_dir: str | Path | Iterable[str | Path],
    *,
    max_cases_per_kind: int = 128,
) -> FeedbackProfile:
    roots = _normalize_run_dirs(run_dir)
    cups: list[_FeedbackCandidate] = []
    pwg: list[_FeedbackCandidate] = []
    images: list[_FeedbackCandidate] = []
    seen: set[tuple[str, tuple[tuple[str, int], ...]]] = set()

    for root in roots:
        timeline = _timeline_records_by_case(root)
        for source, meta_path in _candidate_meta_paths(root):
            try:
                seed = _seed_from_meta(root, meta_path, source)
            except (OSError, json.JSONDecodeError, KeyError, struct.error, ValueError):
                continue
            key = (seed.kind, tuple(sorted(seed.fields.items())))
            if key in seen:
                continue
            seen.add(key)
            record = timeline.get((seed.target_id, seed.case_id), {})
            candidate = _FeedbackCandidate(
                seed=seed,
                score=_candidate_score(seed, source, record),
                diversity_key=_diversity_key(seed),
            )
            if seed.kind == "cups":
                cups.append(candidate)
            elif seed.kind == "pwg":
                pwg.append(candidate)
            elif seed.kind == "image":
                images.append(candidate)

    return FeedbackProfile(
        source_run_dir=":".join(str(root) for root in roots),
        cups=_select_frontier(cups, max_cases_per_kind),
        pwg=_select_frontier(pwg, max_cases_per_kind),
        images=_select_frontier(images, max_cases_per_kind),
    )


def write_feedback_profile(profile: FeedbackProfile, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_feedback_profile(path: str | Path) -> FeedbackProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return FeedbackProfile(
        source_run_dir=str(data.get("source_run_dir", "")),
        cups=[_seed_from_dict(item) for item in data.get("cups", [])],
        pwg=[_seed_from_dict(item) for item in data.get("pwg", [])],
        images=[_seed_from_dict(item) for item in data.get("images", [])],
    )


def _candidate_meta_paths(root: Path) -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = []
    interesting = root / "corpus" / "interesting"
    if interesting.exists():
        paths.extend(("interesting", path) for path in sorted(interesting.glob("*/*/meta.json")))
    unique = root / "quarantine" / "unique"
    if unique.exists():
        paths.extend(("unique-crash", path) for path in sorted(unique.glob("*/meta.json")))
    return paths


def _normalize_run_dirs(run_dir: str | Path | Iterable[str | Path]) -> list[Path]:
    if isinstance(run_dir, (str, Path)):
        return [Path(run_dir)]
    roots = [Path(item) for item in run_dir]
    return roots or [Path(".")]


def _timeline_records_by_case(root: Path, *, max_records: int = 200000) -> dict[tuple[str, int], dict[str, Any]]:
    timeline_path = root / "timeline.jsonl"
    if not timeline_path.exists():
        return {}
    records: dict[tuple[str, int], dict[str, Any]] = {}
    tail: deque[str] = deque(maxlen=max_records)
    try:
        with timeline_path.open("r", encoding="utf-8", errors="replace") as handle:
            tail.extend(handle)
    except OSError:
        return records
    for line in tail:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        target_id = str(record.get("target_id", ""))
        if not target_id or "case_id" not in record:
            continue
        try:
            case_id = int(record["case_id"])
        except (TypeError, ValueError):
            continue
        records[(target_id, case_id)] = record
    return records


def _seed_from_meta(root: Path, meta_path: Path, source: str) -> FeedbackSeed:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    document_path = Path(str(meta["document_path"]))
    if not document_path.is_absolute():
        if document_path.exists():
            document_path = document_path
        elif (root / document_path).exists():
            document_path = root / document_path
        else:
            document_path = Path.cwd() / document_path
    data = document_path.read_bytes()
    kind, fields = _parse_document_fields(data)
    return FeedbackSeed(
        kind=kind,
        source=source,
        target_id=str(meta.get("target_id", "")),
        case_id=int(meta.get("case_id", 0)),
        document_path=str(document_path),
        crashed=bool(meta.get("crashed", False)),
        timed_out=bool(meta.get("timed_out", False)),
        fields=fields,
    )


def _parse_document_fields(data: bytes) -> tuple[str, dict[str, int]]:
    if data.startswith(SYNC_CUPS_RASTER_V3):
        return "cups", _parse_raster_fields(data)
    if data.startswith(SYNC_PWG_RASTER):
        return "pwg", _parse_raster_fields(data)
    if data.startswith(PNG_MAGIC):
        return "image", _parse_png_fields(data)
    if len(data) >= 2 and data[:1] == b"P" and data[1:2] in {b"4", b"5", b"6"}:
        return "image", _parse_pnm_fields(data)
    raise ValueError("not a supported feedback document")


def _parse_raster_fields(data: bytes) -> dict[str, int]:
    if not (data.startswith(SYNC_CUPS_RASTER_V3) or data.startswith(SYNC_PWG_RASTER)):
        raise ValueError("not a supported raster document")
    if len(data) < 4 + HEADER_SIZE:
        raise ValueError("short raster document")
    header = data[4 : 4 + HEADER_SIZE]
    bytes_per_line = _u32(header, OFF_CUPS_BYTES_PER_LINE)
    payload_rows = _infer_payload_rows(len(data), bytes_per_line)
    return {
        "width": _u32(header, OFF_CUPS_WIDTH),
        "height": _u32(header, OFF_CUPS_HEIGHT),
        "bits_per_pixel": _u32(header, OFF_CUPS_BITS_PER_PIXEL),
        "bytes_per_line": bytes_per_line,
        "row_count": _u32(header, OFF_CUPS_ROW_COUNT),
        "payload_rows": payload_rows,
        "color_space": _u32(header, OFF_CUPS_COLOR_SPACE),
        "num_colors": _u32(header, OFF_CUPS_NUM_COLORS),
        "color_order": _u32(header, OFF_CUPS_COLOR_ORDER),
        "compression": _u32(header, OFF_CUPS_COMPRESSION),
        "x_res": _u32(header, OFF_HW_RESOLUTION),
        "y_res": _u32(header, OFF_HW_RESOLUTION + 4),
    }


def _parse_png_fields(data: bytes) -> dict[str, int]:
    if len(data) < 33 or data[12:16] != b"IHDR":
        raise ValueError("short PNG document")
    width, height = struct.unpack(">II", data[16:24])
    bit_depth = data[24]
    color_type = data[25]
    interlace = data[28]
    idat_bytes = 0
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        if chunk_type == b"IDAT":
            idat_bytes += length
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    channels = _png_channels(color_type)
    return {
        "format_id": _image_format_id_from_png(color_type),
        "width": width,
        "height": height,
        "channels": channels,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "interlace": interlace,
        "payload_len": idat_bytes,
        "expected_payload_len": max(1, height * (1 + width * channels)),
    }


def _parse_pnm_fields(data: bytes) -> dict[str, int]:
    tokens, payload_offset = _pnm_tokens_and_payload_offset(data)
    if len(tokens) < 3:
        raise ValueError("short PNM document")
    magic = tokens[0].decode("ascii", errors="replace")
    if magic not in {"P4", "P5", "P6"}:
        raise ValueError("unsupported PNM document")
    width = int(tokens[1])
    height = int(tokens[2])
    maxval = 1 if magic == "P4" else int(tokens[3])
    channels = 3 if magic == "P6" else 1
    sample_bytes = 2 if maxval > 255 else 1
    if magic == "P4":
        expected = ((width + 7) // 8) * height
    else:
        expected = width * height * channels * sample_bytes
    return {
        "format_id": {"P6": 3, "P5": 4, "P4": 5}[magic],
        "width": width,
        "height": height,
        "channels": channels,
        "maxval": maxval,
        "payload_len": max(0, len(data) - payload_offset),
        "expected_payload_len": expected,
        "comment_style": 1 if b"#" in data[:payload_offset] else 0,
    }


def _pnm_tokens_and_payload_offset(data: bytes) -> tuple[list[bytes], int]:
    tokens: list[bytes] = []
    index = 0
    while index < len(data) and len(tokens) < 4:
        while index < len(data) and data[index:index + 1].isspace():
            index += 1
        if index < len(data) and data[index:index + 1] == b"#":
            while index < len(data) and data[index:index + 1] not in {b"\n", b"\r"}:
                index += 1
            continue
        start = index
        while index < len(data) and not data[index:index + 1].isspace():
            index += 1
        if start < index:
            tokens.append(data[start:index])
        if tokens and tokens[0] == b"P4" and len(tokens) >= 3:
            break
    while index < len(data) and data[index:index + 1].isspace():
        index += 1
    return tokens, index


def _image_format_id_from_png(color_type: int) -> int:
    return {0: 0, 2: 1, 6: 2}.get(color_type, 1)


def _png_channels(color_type: int) -> int:
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)


def _infer_payload_rows(total_size: int, bytes_per_line: int) -> int:
    if bytes_per_line <= 0 or total_size <= 4 + HEADER_SIZE:
        return 1
    page_payload = total_size - 4 - HEADER_SIZE
    return max(1, page_payload // bytes_per_line)


def _prioritize(seeds: list[FeedbackSeed]) -> list[FeedbackSeed]:
    return sorted(
        seeds,
        key=lambda seed: (
            not seed.crashed,
            seed.timed_out,
            seed.target_id,
            seed.case_id,
            seed.source,
        ),
    )


def _select_frontier(candidates: list[_FeedbackCandidate], limit: int) -> list[FeedbackSeed]:
    if limit <= 0:
        return []
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            -candidate.score,
            candidate.seed.kind,
            candidate.seed.target_id,
            candidate.seed.case_id,
            candidate.seed.source,
        ),
    )
    selected: list[_FeedbackCandidate] = []
    used_diversity: set[tuple[Any, ...]] = set()
    for candidate in ordered:
        if candidate.diversity_key in used_diversity:
            continue
        selected.append(candidate)
        used_diversity.add(candidate.diversity_key)
        if len(selected) >= limit:
            return [item.seed for item in selected]
    for candidate in ordered:
        if candidate in selected:
            continue
        selected.append(candidate)
        if len(selected) >= limit:
            break
    return [item.seed for item in selected]


def _candidate_score(seed: FeedbackSeed, source: str, record: dict[str, Any]) -> float:
    score = 0.0
    depth_score = _record_depth_score(record)
    if source == "unique-crash":
        score += 900.0
    elif seed.crashed:
        score += 450.0
    if source == "interesting":
        score += 80.0
    if record.get("retained_for_coverage"):
        score += 120.0
    score += min(400.0, depth_score * 22.0)
    if depth_score >= 15 and not seed.crashed:
        score += 240.0
    elif depth_score >= 10 and not seed.crashed:
        score += 90.0
    try:
        score += 12.0 * int(record.get("new_feature_count", 0))
    except (TypeError, ValueError):
        pass
    if record.get("reached_expected_filter"):
        score += 5.0
    if seed.timed_out or record.get("timed_out"):
        score -= 30.0
    if seed.crashed and depth_score < 10:
        score -= 250.0
    score += _field_edge_score(seed.fields)
    if seed.kind == "image":
        score += 10.0
        if seed.fields.get("payload_len") != seed.fields.get("expected_payload_len"):
            score += 10.0
        if seed.fields.get("comment_style"):
            score += 3.0
    return score


def _record_depth_score(record: dict[str, Any]) -> int:
    semantic_shape = record.get("semantic_shape")
    if not isinstance(semantic_shape, dict):
        return 0
    path = semantic_shape.get("path")
    path_score = 0
    if isinstance(path, dict):
        try:
            path_score = int(path.get("depth_score", 0))
        except (TypeError, ValueError):
            path_score = 0
    output = semantic_shape.get("output")
    if not isinstance(output, dict):
        return path_score
    return max(path_score, path_score + _output_feedback_score(output))


def _output_feedback_score(output: dict[str, Any]) -> int:
    fmt = str(output.get("format", ""))
    if fmt == "pdf":
        score = 6
        score += _bucket_score(str(output.get("object_bucket", "0")))
        score += _bucket_score(str(output.get("stream_bucket", "0")))
        score += 2 * _bucket_score(str(output.get("page_bucket", "0")))
        if output.get("has_xref"):
            score += 1
        if output.get("has_trailer"):
            score += 1
        if output.get("has_eof"):
            score += 1
        return score
    if fmt == "postscript":
        return 4 + _bucket_score(str(output.get("page_bucket", "0")))
    if fmt in {"cups-raster", "pwg-raster"}:
        return 5
    if fmt in {"png", "pnm"}:
        return 2
    return 0


def _bucket_score(bucket: str) -> int:
    return {
        "0": 0,
        "1": 1,
        "2-4": 2,
        "5-16": 3,
        "17-64": 4,
        "65-256": 5,
        "gt256": 6,
    }.get(bucket, 0)


def _field_edge_score(fields: dict[str, int]) -> float:
    width = fields.get("width", 0)
    height = fields.get("height", 0)
    bits = fields.get("bits_per_pixel", 0)
    raw_bpl = max(1, (max(1, width) * max(1, bits) + 7) // 8)
    score = 0.0
    if width in {1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 96, 127, 128, 192, 255, 256, 511, 512}:
        score += 4.0
    if height in {1, 2, 3, 8, 16, 31, 32, 63, 64, 127, 128, 255, 256}:
        score += 3.0
    if width * max(1, height) >= 3072:
        score += 8.0
    if width >= max(1, height) * 4 or height >= max(1, width) * 4:
        score += 5.0
    if fields.get("bytes_per_line", raw_bpl) != raw_bpl:
        score += 6.0
    if fields.get("row_count", height) != height:
        score += 6.0
    if fields.get("payload_rows", height) != height:
        score += 6.0
    if "format_id" in fields:
        score += 4.0
    if fields.get("payload_len", fields.get("expected_payload_len", 0)) != fields.get("expected_payload_len", 0):
        score += 6.0
    return score


def _diversity_key(seed: FeedbackSeed) -> tuple[Any, ...]:
    fields = seed.fields
    width = fields.get("width", 0)
    height = fields.get("height", 0)
    bits = fields.get("bits_per_pixel", 0)
    raw_bpl = max(1, (max(1, width) * max(1, bits) + 7) // 8)
    return (
        seed.target_id,
        seed.kind,
        _bucket(width),
        _bucket(height),
        bits,
        fields.get("color_space", 0),
        fields.get("num_colors", 0),
        _delta_bucket(fields.get("bytes_per_line", raw_bpl) - raw_bpl),
        _delta_bucket(fields.get("row_count", height) - height),
        _delta_bucket(fields.get("payload_rows", height) - height),
        fields.get("format_id", -1),
        _delta_bucket(fields.get("payload_len", fields.get("expected_payload_len", 0)) - fields.get("expected_payload_len", 0)),
    )


def _bucket(value: int) -> str:
    if value <= 1:
        return "one"
    if value <= 8:
        return "tiny"
    if value <= 32:
        return "small"
    if value <= 128:
        return "medium"
    return "large"


def _delta_bucket(delta: int) -> str:
    if delta == 0:
        return "exact"
    if delta < 0:
        return "short" if delta >= -4 else "very-short"
    return "long" if delta <= 4 else "very-long"


def _seed_from_dict(item: dict[str, Any]) -> FeedbackSeed:
    return FeedbackSeed(
        kind=str(item["kind"]),
        source=str(item.get("source", "")),
        target_id=str(item.get("target_id", "")),
        case_id=int(item.get("case_id", 0)),
        document_path=str(item.get("document_path", "")),
        crashed=bool(item.get("crashed", False)),
        timed_out=bool(item.get("timed_out", False)),
        fields={str(key): int(value) for key, value in dict(item.get("fields", {})).items()},
    )


def _u32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]
