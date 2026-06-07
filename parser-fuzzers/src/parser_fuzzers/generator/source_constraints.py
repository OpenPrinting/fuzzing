from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
CONTROL_RE = re.compile(
    r"\b(if|else\s+if|switch|case|while|for|assert|return)\b|"
    r"\b(strcasecmp|strcmp|strncmp|memcmp|memchr|strstr)\b"
)
OP_RE = re.compile(r"==|!=|<=|>=|<|>")
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


FIELD_PATTERNS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("width", ("cups", "pwg"), (r"\bcupsWidth\b", r"\bwidth\b", r"\bWidth\b")),
    ("height", ("cups", "pwg"), (r"\bcupsHeight\b", r"\bheight\b", r"\bHeight\b")),
    (
        "bytes_per_line",
        ("cups", "pwg"),
        (r"\bcupsBytesPerLine\b", r"\bbytes[_-]?per[_-]?line\b", r"\bBytesPerLine\b"),
    ),
    (
        "bits_per_pixel",
        ("cups", "pwg"),
        (r"\bcupsBitsPerPixel\b", r"\bbits[_-]?per[_-]?pixel\b", r"\bBitsPerPixel\b"),
    ),
    ("row_count", ("cups", "pwg"), (r"\bcupsRowCount\b", r"\brow[_-]?count\b", r"\bRowCount\b")),
    ("payload_rows", ("cups", "pwg"), (r"\bpayload[_-]?rows\b", r"\bdata[_-]?rows\b", r"\brows[_-]?written\b")),
    ("x_res", ("cups", "pwg", "ppd"), (r"\bHWResolution\b", r"\bx[_-]?res\b", r"\bResolution\b")),
    ("y_res", ("cups", "pwg", "ppd"), (r"\bHWResolution\b", r"\by[_-]?res\b", r"\bResolution\b")),
    ("color_space", ("cups",), (r"\bcupsColorSpace\b", r"\bColorSpace\b")),
    ("num_colors", ("cups",), (r"\bcupsNumColors\b", r"\bNumColors\b")),
    ("color_order", ("cups",), (r"\bcupsColorOrder\b", r"\bColorOrder\b")),
    ("compression", ("cups",), (r"\bcupsCompression\b", r"\bCompression\b")),
)

OPTION_TOKENS = {
    "PageSize",
    "PageRegion",
    "ColorModel",
    "PrintQuality",
    "MediaType",
    "Duplex",
    "Resolution",
    "HWResolution",
    "cupsFilter",
    "cupsManualCopies",
    "cupsColorSpace",
    "cupsBitsPerPixel",
    "cupsBytesPerLine",
}

DYNAMIC_TOKEN_FIELD_MAP: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "cupsBytesPerLine": (("bytes_per_line", ("cups", "pwg")),),
    "cupsBitsPerPixel": (("bits_per_pixel", ("cups", "pwg")),),
    "cupsColorSpace": (("color_space", ("cups",)),),
    "HWResolution": (("x_res", ("cups", "pwg", "ppd")), ("y_res", ("cups", "pwg", "ppd"))),
    "Resolution": (("x_res", ("cups", "pwg", "ppd")), ("y_res", ("cups", "pwg", "ppd"))),
    "PageSize": (("width", ("ppd",)), ("height", ("ppd",))),
    "PageRegion": (("width", ("ppd",)), ("height", ("ppd",))),
    "ColorModel": (("color_space", ("cups", "ppd")),),
    "cupsFilter": (),
}


@dataclass(frozen=True)
class SourceHint:
    source_path: str
    line: int
    text: str
    families: tuple[str, ...]
    fields: tuple[str, ...]
    operators: tuple[str, ...]
    strings: tuple[str, ...]
    kind: str


def mine_source_constraints(
    source_roots: Sequence[str | Path],
    *,
    max_records: int = 2000,
) -> dict[str, Any]:
    records: list[SourceHint] = []
    files_scanned = 0
    lines_scanned = 0
    field_counts: dict[str, dict[str, int]] = {"cups": {}, "pwg": {}, "ppd": {}}
    option_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}

    for source_file in _iter_source_files(source_roots):
        files_scanned += 1
        path_text = str(source_file)
        path_family = _family_from_path(path_text)
        try:
            lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            lines_scanned += 1
            hint = _hint_from_line(source_file, line_no, line, path_family)
            if hint is None:
                continue
            for family in hint.families:
                counts = field_counts.setdefault(family, {})
                for field in hint.fields:
                    counts[field] = counts.get(field, 0) + 1
            for token in hint.strings:
                if token in OPTION_TOKENS:
                    option_counts[token] = option_counts.get(token, 0) + 1
            kind_counts[hint.kind] = kind_counts.get(hint.kind, 0) + 1
            if len(records) < max_records:
                records.append(hint)

    profile = {
        "schema_version": "source-constraint-hints-v1",
        "source_roots": [str(Path(root)) for root in source_roots],
        "summary": {
            "files_scanned": files_scanned,
            "lines_scanned": lines_scanned,
            "records": len(records),
            "records_truncated": len(records) >= max_records,
            "kind_counts": dict(sorted(kind_counts.items())),
        },
        "families": {
            family: {"fields": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))}
            for family, counts in sorted(field_counts.items())
        },
        "ppd_options": dict(sorted(option_counts.items(), key=lambda item: (-item[1], item[0]))),
        "records": [asdict(record) for record in records],
        "template_bias": _template_bias(field_counts),
    }
    return profile


def write_source_constraint_profile(profile: dict[str, Any], output_path: str | Path) -> None:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_source_constraint_profile(path: str | Path) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def active_source_constraint_key() -> str:
    source_path = os.environ.get("SMT_FUZZER_SOURCE_CONSTRAINTS", "").strip()
    dynamic_path = os.environ.get("SMT_FUZZER_DYNAMIC_CONSTRAINTS", "").strip()
    if not source_path and not dynamic_path:
        return ""
    parts = []
    for path in (source_path, dynamic_path):
        if path:
            parts.append(_profile_identity(path))
    rate = os.environ.get("SMT_FUZZER_SOURCE_CONSTRAINT_RATE", "")
    return f"{'|'.join(parts)}:rate={rate}"


def _profile_identity(path: str) -> str:
    resolved = Path(path)
    try:
        stat = resolved.stat()
        return f"{resolved.resolve()}:{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        return str(resolved)


def choose_source_objective(
    spec_name: str,
    objectives: Sequence[Any],
    slot: int,
) -> tuple[Any, bool]:
    default = objectives[slot % len(objectives)]
    profile = _active_profile()
    if not profile or not _source_rate_allows(slot):
        return default, False
    family = _family_from_spec(spec_name)
    preferred = _preferred_objective_names(profile, family)
    if not preferred:
        return default, False
    by_name = {getattr(objective, "name", ""): objective for objective in objectives}
    candidates = [by_name[name] for name in preferred if name in by_name]
    if not candidates:
        return default, False
    return candidates[(slot // max(1, len(objectives))) % len(candidates)], True


def choose_source_feedback_variant(family: str, variant_count: int, slot: int) -> tuple[int, bool]:
    default = slot % variant_count
    profile = _active_profile()
    if not profile or not _source_rate_allows(slot):
        return default, False
    variants = _preferred_feedback_variants(profile, family)
    variants = [variant for variant in variants if 0 <= variant < variant_count]
    if not variants:
        return default, False
    return variants[(slot // max(1, variant_count)) % len(variants)], True


def _iter_source_files(source_roots: Sequence[str | Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in source_roots:
        path = Path(root)
        if path.is_file() and path.suffix in SOURCE_EXTENSIONS:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield path
            continue
        if not path.exists():
            continue
        for source_file in sorted(path.rglob("*")):
            if source_file.is_file() and source_file.suffix in SOURCE_EXTENSIONS:
                resolved = source_file.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                yield source_file


def _hint_from_line(source_file: Path, line_no: int, line: str, path_family: str) -> SourceHint | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return None
    fields, field_families = _fields_in_line(stripped)
    strings = _strings_in_line(stripped)
    operators = tuple(sorted(set(OP_RE.findall(stripped))))
    control = CONTROL_RE.search(stripped) is not None
    interesting_string = any(token in OPTION_TOKENS or token.startswith("application/") for token in strings)
    if not fields and not interesting_string:
        return None
    if not control and not operators and not interesting_string:
        return None

    families = set(field_families)
    if path_family:
        families.add(path_family)
    if interesting_string:
        families.add("ppd")
    kind = _hint_kind(stripped, operators, strings)
    return SourceHint(
        source_path=str(source_file),
        line=line_no,
        text=stripped[:240],
        families=tuple(sorted(families or {"unknown"})),
        fields=tuple(sorted(fields)),
        operators=operators,
        strings=strings,
        kind=kind,
    )


def _fields_in_line(line: str) -> tuple[set[str], set[str]]:
    fields: set[str] = set()
    families: set[str] = set()
    for name, mapped_families, patterns in FIELD_PATTERNS:
        if any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in patterns):
            fields.add(name)
            families.update(mapped_families)
    return fields, families


def _strings_in_line(line: str) -> tuple[str, ...]:
    values = []
    for match in STRING_RE.finditer(line):
        value = match.group(1)
        if len(value) > 96:
            continue
        if value in OPTION_TOKENS or value.startswith("application/") or value in {"RaS2", "3SaR", "2SaR"}:
            values.append(value)
    return tuple(sorted(set(values)))


def _hint_kind(line: str, operators: tuple[str, ...], strings: tuple[str, ...]) -> str:
    if any(func in line for func in ("strcmp", "strcasecmp", "strncmp", "memcmp", "strstr")):
        return "string-or-memory-compare"
    if "switch" in line or re.search(r"\bcase\b", line):
        return "switch-or-case"
    if operators:
        return "bounds-or-equality"
    if strings:
        return "string-token"
    return "field-reference"


def _family_from_path(path_text: str) -> str:
    lower = path_text.lower()
    if "ppd" in lower:
        return "ppd"
    if "pwg" in lower:
        return "pwg"
    if "raster" in lower or "cups" in lower:
        return "cups"
    return ""


def _family_from_spec(spec_name: str) -> str:
    lower = spec_name.lower()
    if "pwg" in lower:
        return "pwg"
    if "cups" in lower:
        return "cups"
    return "cups"


def _template_bias(field_counts: dict[str, dict[str, int]]) -> dict[str, Any]:
    return {
        family: {
            "preferred_objectives": _objective_names_from_fields(counts, cups=(family == "cups")),
            "preferred_feedback_variants": _feedback_variants_from_fields(counts),
        }
        for family, counts in sorted(field_counts.items())
    }


def _preferred_objective_names(profile: dict[str, Any], family: str) -> list[str]:
    bias = profile.get("template_bias", {}).get(family, {})
    names = bias.get("preferred_objectives", [])
    return [str(name) for name in names]


def _preferred_feedback_variants(profile: dict[str, Any], family: str) -> list[int]:
    bias = profile.get("template_bias", {}).get(family, {})
    variants = bias.get("preferred_feedback_variants", [])
    parsed = []
    for variant in variants:
        try:
            parsed.append(int(variant))
        except (TypeError, ValueError):
            continue
    return parsed


def _objective_names_from_fields(counts: dict[str, int], *, cups: bool) -> list[str]:
    names: list[str] = []
    if counts.get("bytes_per_line", 0):
        names.extend(["short_line", "padded_line", "valid_tight" if cups else "valid_exact"])
    if counts.get("row_count", 0):
        names.extend(["row_count_short", "row_count_long"])
    if counts.get("payload_rows", 0):
        names.extend(["payload_short", "payload_extra"])
    if counts.get("width", 0) or counts.get("height", 0) or counts.get("bits_per_pixel", 0):
        names.extend(["valid_aligned" if cups else "valid_exact", "padded_line"])
    if counts.get("x_res", 0) or counts.get("y_res", 0):
        names.extend(["valid_aligned" if cups else "valid_exact"])
    return _unique(names)


def _feedback_variants_from_fields(counts: dict[str, int]) -> list[int]:
    variants: list[int] = []
    if counts.get("bytes_per_line", 0):
        variants.extend([1, 2, 3, 4, 9, 10])
    if counts.get("row_count", 0):
        variants.extend([5, 6, 11, 12])
    if counts.get("payload_rows", 0):
        variants.extend([7, 8, 12, 13])
    if counts.get("width", 0) or counts.get("height", 0) or counts.get("bits_per_pixel", 0):
        variants.extend([0, 2, 10])
    return _unique_ints(variants)


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _unique_ints(values: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    result: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _source_rate_allows(slot: int) -> bool:
    rate = _source_rate()
    if rate <= 0:
        return False
    if rate >= 1:
        return True
    bucket = ((slot + 1) * 1103515245 + 12345) % 10000
    return bucket < int(rate * 10000)


def _source_rate() -> float:
    value = os.environ.get("SMT_FUZZER_SOURCE_CONSTRAINT_RATE", "0.5")
    try:
        return max(0.0, min(1.0, float(value)))
    except ValueError:
        return 0.5


def _active_profile() -> dict[str, Any]:
    source_path = os.environ.get("SMT_FUZZER_SOURCE_CONSTRAINTS", "").strip()
    dynamic_path = os.environ.get("SMT_FUZZER_DYNAMIC_CONSTRAINTS", "").strip()
    profiles = []
    if source_path:
        profiles.append(_cached_profile(source_path))
    if dynamic_path:
        dynamic_profile = _cached_profile(dynamic_path)
        profiles.append(_source_profile_from_dynamic(dynamic_profile))
    if not profiles:
        return {}
    return _merge_profiles(profiles)


def _cached_profile(path: str) -> dict[str, Any]:
    # Manual cache keeps patched test environments predictable because the key is
    # the file identity, not unrelated global state.
    cache = getattr(_cached_profile, "_cache", {})
    try:
        stat = Path(path).stat()
        key = f"{path}:{stat.st_mtime_ns}:{stat.st_size}"
    except OSError:
        key = path
    if key not in cache:
        cache[key] = load_source_constraint_profile(path)
        setattr(_cached_profile, "_cache", cache)
    return cache[key]


def _source_profile_from_dynamic(profile: dict[str, Any]) -> dict[str, Any]:
    field_counts: dict[str, dict[str, int]] = {"cups": {}, "pwg": {}, "ppd": {}}
    tokens: dict[str, int] = {}
    for source in (profile.get("tokens", {}), profile.get("ppd_options", {}), profile.get("magic_tokens", {})):
        if isinstance(source, dict):
            for token, count in source.items():
                try:
                    tokens[str(token)] = tokens.get(str(token), 0) + int(count)
                except (TypeError, ValueError):
                    continue
    for token, count in tokens.items():
        for field, families in DYNAMIC_TOKEN_FIELD_MAP.get(token, ()):
            for family in families:
                family_counts = field_counts.setdefault(family, {})
                family_counts[field] = family_counts.get(field, 0) + count
    return {
        "schema_version": "source-constraint-hints-v1+dynamic",
        "summary": {"dynamic_compare_records": profile.get("summary", {}).get("compare_records", 0)},
        "families": {
            family: {"fields": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))}
            for family, counts in sorted(field_counts.items())
        },
        "ppd_options": dict(profile.get("ppd_options", {})),
        "records": [],
        "template_bias": _template_bias(field_counts),
    }


def _merge_profiles(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    field_counts: dict[str, dict[str, int]] = {"cups": {}, "pwg": {}, "ppd": {}}
    ppd_options: dict[str, int] = {}
    for profile in profiles:
        families = profile.get("families", {})
        if isinstance(families, dict):
            for family, payload in families.items():
                fields = payload.get("fields", {}) if isinstance(payload, dict) else {}
                if not isinstance(fields, dict):
                    continue
                family_counts = field_counts.setdefault(str(family), {})
                for field, count in fields.items():
                    try:
                        family_counts[str(field)] = family_counts.get(str(field), 0) + int(count)
                    except (TypeError, ValueError):
                        continue
        options = profile.get("ppd_options", {})
        if isinstance(options, dict):
            for token, count in options.items():
                try:
                    ppd_options[str(token)] = ppd_options.get(str(token), 0) + int(count)
                except (TypeError, ValueError):
                    continue
    return {
        "schema_version": "source-constraint-hints-v1+merged",
        "families": {
            family: {"fields": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))}
            for family, counts in sorted(field_counts.items())
        },
        "ppd_options": dict(sorted(ppd_options.items(), key=lambda item: (-item[1], item[0]))),
        "records": [],
        "template_bias": _template_bias(field_counts),
    }
