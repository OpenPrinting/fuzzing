from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any


MAGIC = b"SMT_PWG_BUNDLE_V1\n"
PPD_MARK = b"--SMT-PPD--\n"
OPTIONS_MARK = b"--SMT-OPTIONS--\n"
DOCUMENT_MARK = b"--SMT-DOCUMENT--\n"

PPD_OPTION_VALUES = {
    "PageSize": "Letter",
    "PageRegion": "Letter",
    "ColorModel": "RGB",
    "Duplex": "None",
    "MediaType": "Plain",
    "PrintQuality": "Normal",
    "Resolution": "300dpi",
    "HWResolution": "300dpi",
    "cupsBitsPerPixel": "24",
    "cupsBytesPerLine": "24",
    "cupsColorOrder": "0",
    "cupsColorSpace": "19",
    "cupsCompression": "0",
    "cupsManualCopies": "True",
    "cupsFilter": "application/vnd.cups-pwg application/pdf 0 -",
}

STATIC_BUNDLE_TOKENS = [
    "SMT_PWG_BUNDLE_V1",
    "--SMT-PPD--",
    "--SMT-OPTIONS--",
    "--SMT-DOCUMENT--",
    "*PPD-Adobe:",
    "*cupsFilter2:",
    "*OpenUI",
    "*CloseUI",
    "PageSize=",
    "PageRegion=",
    "ColorModel=",
    "PrintQuality=",
    "MediaType=",
    "Duplex=",
    "Resolution=",
    "application/vnd.cups-pwg",
    "application/pdf",
    "2SaR",
    "RaS2",
]

TARGET_RELEVANT_PATTERNS = [
    re.compile(r"^(?:application|image|text|printer)/[A-Za-z0-9_.+/-]+$"),
    re.compile(r"^(?:cups|media|print|page|color|duplex|resolution|orientation|output)-[A-Za-z0-9_.-]+$"),
    re.compile(r"^(?:cups[A-Z]|Page|Color|Duplex|Media|Print|Resolution|HWResolution)[A-Za-z0-9]*$"),
]


def load_dynamic_profile(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def extract_dynamic_tokens(profile: dict[str, Any], *, max_tokens: int = 512) -> list[str]:
    weighted: dict[str, int] = {}

    def add_token(raw: Any, weight: int = 1) -> None:
        token = _normalize_token(raw)
        if not token or not _target_relevant_token(token):
            return
        weighted[token] = weighted.get(token, 0) + max(1, weight)
        for variant in _token_variants(token):
            weighted[variant] = weighted.get(variant, 0) + max(1, weight // 2)

    for section in ("tokens", "ppd_options", "magic_tokens"):
        values = profile.get(section)
        if isinstance(values, dict):
            for token, count in values.items():
                add_token(token, _safe_int(count, 1))

    records = profile.get("records")
    if isinstance(records, list):
        for record in records[: max(0, max_tokens * 4)]:
            if not isinstance(record, dict):
                continue
            for token in record.get("tokens") or []:
                add_token(token, 1)
            for key in ("a_ascii", "b_ascii"):
                value = str(record.get(key) or "")
                if _target_relevant_token(value):
                    add_token(value, 1)

    for token in STATIC_BUNDLE_TOKENS:
        add_token(token, 16)

    return [
        token
        for token, _ in sorted(
            weighted.items(),
            key=lambda item: (-item[1], len(item[0]), item[0]),
        )[:max_tokens]
    ]


def write_dynamic_afl_dictionary(
    profile_path: str | Path,
    output_path: str | Path,
    *,
    base_dictionary: str | Path | None = None,
    max_tokens: int = 512,
) -> dict[str, Any]:
    profile = load_dynamic_profile(profile_path)
    tokens = extract_dynamic_tokens(profile, max_tokens=max_tokens)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    seen_values: set[str] = set()
    if base_dictionary:
        base_path = Path(base_dictionary)
        if base_path.exists():
            for line in base_path.read_text(encoding="utf-8").splitlines():
                value = _parse_afl_dict_value(line)
                if value:
                    seen_values.add(value)
                lines.append(line)

    lines.append("# dynamic compare tokens")
    added = 0
    for token in tokens:
        if token in seen_values:
            continue
        lines.append(_afl_quote(token))
        seen_values.add(token)
        added += 1

    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {
        "profile_path": str(profile_path),
        "output_path": str(output),
        "base_dictionary": str(base_dictionary) if base_dictionary else "",
        "tokens_extracted": len(tokens),
        "tokens_added": added,
        "dictionary_entries": len([line for line in lines if _parse_afl_dict_value(line)]),
    }


def augment_pwg_bundle_seed_dir(
    seed_dir: str | Path,
    profile_path: str | Path,
    *,
    output_dir: str | Path | None = None,
    limit: int = 64,
) -> dict[str, Any]:
    seed_root = Path(seed_dir)
    destination = Path(output_dir) if output_dir else seed_root
    destination.mkdir(parents=True, exist_ok=True)
    if destination != seed_root:
        for seed in sorted(seed_root.glob("*.pwg-bundle")):
            shutil.copy2(seed, destination / seed.name)

    profile = load_dynamic_profile(profile_path)
    tokens = extract_dynamic_tokens(profile, max_tokens=max(16, limit * 2))
    option_names = _dynamic_option_names(profile, tokens)
    base_seeds = sorted(destination.glob("*.pwg-bundle"))
    if not base_seeds:
        raise FileNotFoundError(f"no .pwg-bundle seeds found in {destination}")

    created: list[dict[str, str]] = []
    for idx, option in enumerate(option_names):
        if len(created) >= limit:
            break
        base = base_seeds[idx % len(base_seeds)]
        bundle = parse_pwg_bundle(base.read_bytes())
        if bundle is None:
            continue
        ppd, options, document = bundle
        value = PPD_OPTION_VALUES.get(option, "1")
        out = destination / f"dynamic-option-{idx:04d}-{_safe_name(option)}.pwg-bundle"
        out.write_bytes(
            compose_pwg_bundle(
                ppd + _ppd_dynamic_block(option, value),
                _append_job_option(options, option, value),
                document,
            )
        )
        created.append({"path": str(out), "source": str(base), "option": option, "value": value})

    if len(created) < limit and tokens:
        base = base_seeds[0]
        bundle = parse_pwg_bundle(base.read_bytes())
        if bundle is not None:
            ppd, options, document = bundle
            rich_options = option_names[:16]
            out = destination / "dynamic-rich-compare-profile.pwg-bundle"
            for option in rich_options:
                ppd += _ppd_dynamic_block(option, PPD_OPTION_VALUES.get(option, "1"))
                options = _append_job_option(options, option, PPD_OPTION_VALUES.get(option, "1"))
            for token in tokens[:32]:
                if token.startswith(("application/", "image/", "text/")):
                    ppd += f'\n*cupsFilter2: "{token} application/pdf 0 -"\n'.encode()
            out.write_bytes(compose_pwg_bundle(ppd, options, document))
            created.append({"path": str(out), "source": str(base), "option": "rich", "value": "dynamic-profile"})

    manifest = {
        "profile_path": str(profile_path),
        "seed_dir": str(seed_root),
        "output_dir": str(destination),
        "requested_limit": limit,
        "created": len(created),
        "variants": created,
    }
    (destination / "dynamic_seed_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def parse_pwg_bundle(data: bytes) -> tuple[bytes, bytes, bytes] | None:
    if not data.startswith(MAGIC):
        return None
    ppd_mark = data.find(PPD_MARK)
    options_mark = data.find(OPTIONS_MARK)
    document_mark = data.find(DOCUMENT_MARK)
    if ppd_mark < 0 or options_mark < 0 or document_mark < 0:
        return None
    if not (ppd_mark < options_mark < document_mark):
        return None
    ppd_start = ppd_mark + len(PPD_MARK)
    options_start = options_mark + len(OPTIONS_MARK)
    document_start = document_mark + len(DOCUMENT_MARK)
    return data[ppd_start:options_mark], data[options_start:document_mark], data[document_start:]


def compose_pwg_bundle(ppd: bytes, options: bytes, document: bytes) -> bytes:
    return MAGIC + PPD_MARK + ppd + b"\n" + OPTIONS_MARK + options + b"\n" + DOCUMENT_MARK + document


def _dynamic_option_names(profile: dict[str, Any], tokens: list[str]) -> list[str]:
    names: list[str] = []
    ppd_options = profile.get("ppd_options")
    if isinstance(ppd_options, dict):
        names.extend(str(name) for name in ppd_options)
    for token in tokens:
        bare = token.strip("*:=").split("=", 1)[0]
        if bare in PPD_OPTION_VALUES:
            names.append(bare)
    for fallback in PPD_OPTION_VALUES:
        names.append(fallback)
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name in seen or name not in PPD_OPTION_VALUES:
            continue
        deduped.append(name)
        seen.add(name)
    return deduped


def _ppd_dynamic_block(option: str, value: str) -> bytes:
    if option == "PageSize":
        text = """
*DefaultPageSize: Letter
*PageSize Letter/Letter: "<</PageSize[612 792]>>setpagedevice"
"""
    elif option == "PageRegion":
        text = """
*DefaultPageRegion: Letter
*PageRegion Letter/Letter: "<</PageSize[612 792]>>setpagedevice"
"""
    elif option == "Resolution":
        text = """
*DefaultResolution: 300dpi
*Resolution 300dpi/300 dpi: ""
"""
    elif option == "HWResolution":
        text = """
*DefaultHWResolution: 300dpi
*HWResolution 300dpi/300 dpi: ""
"""
    elif option == "ColorModel":
        text = """
*DefaultColorModel: RGB
*ColorModel RGB/RGB: ""
"""
    elif option == "Duplex":
        text = """
*DefaultDuplex: None
*Duplex None/Off: ""
"""
    elif option == "MediaType":
        text = """
*DefaultMediaType: Plain
*MediaType Plain/Plain: ""
"""
    elif option == "PrintQuality":
        text = """
*DefaultPrintQuality: Normal
*PrintQuality Normal/Normal: ""
"""
    elif option == "cupsFilter":
        text = f'\n*cupsFilter2: "{value}"\n'
    else:
        text = f"\n*{option}: {value}\n"
    return text.encode("utf-8")


def _append_job_option(options: bytes, option: str, value: str) -> bytes:
    if option == "cupsFilter":
        return options
    clean = options.strip()
    fragment = f"{option}={value}".encode("utf-8")
    return fragment if not clean else clean + b" " + fragment


def _token_variants(token: str) -> list[str]:
    variants: list[str] = []
    if token in PPD_OPTION_VALUES:
        variants.extend([f"{token}=", f"*{token}:", f"*Default{token}:"])
    elif token.startswith("cups") and re.match(r"^[A-Za-z][A-Za-z0-9]+$", token):
        variants.extend([f"{token}=", f"*{token}:"])
    return variants


def _target_relevant_token(token: str) -> bool:
    if token in STATIC_BUNDLE_TOKENS or token in PPD_OPTION_VALUES:
        return True
    if not 2 <= len(token) <= 96:
        return False
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in token):
        return False
    if any(pattern.match(token) for pattern in TARGET_RELEVANT_PATTERNS):
        return True
    return token in {"2SaR", "RaS2", "RGB", "CMYK", "Gray", "Black", "Letter", "A4"}


def _normalize_token(raw: Any) -> str:
    token = str(raw or "").strip().strip("\x00")
    token = token.replace("\x00", "")
    token = re.sub(r"[.]{2,}$", "", token)
    token = token.strip()
    return token


def _afl_quote(token: str) -> str:
    escaped = []
    for byte in token.encode("utf-8", errors="replace"):
        ch = chr(byte)
        if ch == "\\":
            escaped.append("\\\\")
        elif ch == '"':
            escaped.append('\\"')
        elif 32 <= byte <= 126:
            escaped.append(ch)
        else:
            escaped.append(f"\\x{byte:02x}")
    return '"' + "".join(escaped) + '"'


def _parse_afl_dict_value(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if stripped.startswith('"') and stripped.endswith('"') and len(stripped) >= 2:
        return stripped[1:-1]
    if "=" in stripped:
        _, value = stripped.split("=", 1)
        value = value.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            return value[1:-1]
    return ""


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:80]
