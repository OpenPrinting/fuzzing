from __future__ import annotations

import hashlib
import json
import re
import shlex
import struct
import zlib
from pathlib import Path
from typing import Any


def build_planned_shape(
    *,
    target_id: str,
    ppd_kind: str,
    document_kind: str,
    input_mime: str,
    output_mime: str,
    expected_filters: list[str],
    ppd_text: str,
    document_data: bytes,
    job_options: str = "",
) -> dict[str, Any]:
    semantic_input = _semantic_input_shape(
        target_id=target_id,
        ppd_kind=ppd_kind,
        document_kind=document_kind,
        input_mime=input_mime,
        output_mime=output_mime,
        expected_filters=expected_filters,
        ppd_shape=parse_ppd_text(ppd_text),
        document_shape=parse_document_bytes(document_data),
        job_options_shape=parse_job_options(job_options),
    )
    return {
        "semantic_input": semantic_input,
        "semantic_input_hash": stable_hash(semantic_input),
        "labels": _labels_for_semantic_input(semantic_input),
    }


def build_result_shape_bundle(result: Any, stderr_text: str | None = None) -> dict[str, Any]:
    ppd_text = _read_text(_get(result, "ppd_path", ""))
    document_data = _read_bytes(_get(result, "document_path", ""))
    output_data = _read_bytes(_get(result, "stdout_path", ""))
    stderr = stderr_text if stderr_text is not None else _read_text(_get(result, "stderr_path", ""))
    semantic_input = _semantic_input_shape(
        target_id=str(_get(result, "target_id", "")),
        ppd_kind=str(_get(result, "ppd_kind", "")),
        document_kind=str(_get(result, "document_kind", "")),
        input_mime="",
        output_mime="",
        expected_filters=[str(value) for value in _get(result, "filters", [])],
        ppd_shape=parse_ppd_text(ppd_text),
        document_shape=parse_document_bytes(document_data),
        job_options_shape=parse_job_options(str(_get(result, "job_options", ""))),
    )
    path_shape = parse_path_shape(result, stderr)
    output_shape = parse_output_bytes(output_data)
    failure_shape = parse_failure_shape(result, stderr)
    semantic_input_hash = stable_hash(semantic_input)
    path_shape_hash = stable_hash(path_shape)
    output_shape_hash = stable_hash(output_shape)
    failure_shape_hash = stable_hash(failure_shape)
    compound = {
        "semantic_input_hash": semantic_input_hash,
        "path_shape_hash": path_shape_hash,
        "output_shape_hash": output_shape_hash,
        "failure_shape_hash": failure_shape_hash,
    }
    return {
        "semantic_input": semantic_input,
        "semantic_input_hash": semantic_input_hash,
        "path_shape": path_shape,
        "path_shape_hash": path_shape_hash,
        "output_shape": output_shape,
        "output_shape_hash": output_shape_hash,
        "failure_shape": failure_shape,
        "failure_shape_hash": failure_shape_hash,
        "compound_shape_hash": stable_hash(compound),
        "labels": {
            **_labels_for_semantic_input(semantic_input),
            **_labels_for_path(path_shape),
            **_labels_for_output(output_shape),
            **_labels_for_failure(failure_shape),
        },
    }


def semantic_runtime_key(target_id: str, semantic_input_hash: str) -> str:
    return f"target:{target_id}|semantic-input:{semantic_input_hash}"


def shape_feature_tokens(shape_bundle: dict[str, Any]) -> set[str]:
    labels = shape_bundle.get("labels") if isinstance(shape_bundle.get("labels"), dict) else {}
    path_shape = shape_bundle.get("path_shape") if isinstance(shape_bundle.get("path_shape"), dict) else {}
    output_shape = shape_bundle.get("output_shape") if isinstance(shape_bundle.get("output_shape"), dict) else {}
    failure_shape = shape_bundle.get("failure_shape") if isinstance(shape_bundle.get("failure_shape"), dict) else {}
    semantic_hash = str(shape_bundle.get("semantic_input_hash") or "")
    output_hash = str(shape_bundle.get("output_shape_hash") or "")
    failure_hash = str(shape_bundle.get("failure_shape_hash") or "")
    features: set[str] = set()
    if semantic_hash:
        features.add(f"shape-input:{semantic_hash}")
    if output_hash:
        features.add(f"shape-output:{output_hash}")
    if failure_hash:
        features.add(f"shape-failure:{failure_hash}")
    for key, value in sorted(labels.items()):
        if value not in {"", None}:
            features.add(f"shape-{key}:{value}")
    for state in path_shape.get("stderr_states", []):
        if state:
            features.add(f"shape-path-state:{state}")
    depth = combined_depth_score(shape_bundle)
    features.add(f"shape-path-depth:{_depth_bucket(depth)}")
    if output_shape.get("format"):
        features.add(f"shape-output-format:{output_shape.get('format', '')}")
    if output_shape.get("structure"):
        features.add(f"shape-output-structure:{str(output_shape.get('structure', ''))[:80]}")
    if output_shape:
        features.add(f"shape-output-depth:{_depth_bucket(output_depth_score(output_shape))}")
    features.add(f"shape-pipeline:{_pipeline_label(path_shape, output_shape)}")
    if failure_shape.get("location"):
        features.add(f"shape-failure-site:{failure_shape['location']}")
    return features


def compact_shape_record(shape_bundle: dict[str, Any]) -> dict[str, Any]:
    semantic = shape_bundle.get("semantic_input", {})
    ppd = semantic.get("ppd", {}) if isinstance(semantic, dict) else {}
    document = semantic.get("document", {}) if isinstance(semantic, dict) else {}
    job_options = semantic.get("job_options", {}) if isinstance(semantic, dict) else {}
    path_shape = shape_bundle.get("path_shape", {})
    output_shape = shape_bundle.get("output_shape", {})
    failure_shape = shape_bundle.get("failure_shape", {})
    depth = combined_depth_score(shape_bundle)
    return {
        "semantic_input_hash": shape_bundle.get("semantic_input_hash", ""),
        "path_shape_hash": shape_bundle.get("path_shape_hash", ""),
        "output_shape_hash": shape_bundle.get("output_shape_hash", ""),
        "failure_shape_hash": shape_bundle.get("failure_shape_hash", ""),
        "compound_shape_hash": shape_bundle.get("compound_shape_hash", ""),
        "ppd": {
            "filter_chain": ppd.get("filter_chain", []),
            "page_class": ppd.get("page_class", ""),
            "resolution_class": ppd.get("resolution_class", ""),
            "color_model": ppd.get("default_color_model", ""),
        },
        "document": {
            "format": document.get("format", ""),
            "image_class": document.get("image_class", ""),
            "structure": document.get("structure", ""),
            "validity": document.get("validity", ""),
        },
        "job_options": {
            "keys": job_options.get("keys", []),
            "page_size": job_options.get("PageSize", ""),
            "color_model": job_options.get("ColorModel", ""),
            "resolution": job_options.get("Resolution", ""),
            "scaling": job_options.get("scaling", ""),
            "orientation": job_options.get("orientation-requested", ""),
        },
        "path": {
            "filter_chain": path_shape.get("filter_chain", []),
            "reached": path_shape.get("reached_expected_filter", False),
            "return_class": path_shape.get("return_class", ""),
            "stderr_states": path_shape.get("stderr_states", []),
            "depth_score": depth,
            "depth_bucket": _depth_bucket(depth),
            "path_only_depth_score": path_depth_score(path_shape),
            "output_depth_score": output_depth_score(output_shape),
        },
        "output": {
            "format": output_shape.get("format", ""),
            "size_bucket": output_shape.get("size_bucket", ""),
            "validity": output_shape.get("validity", ""),
            "structure": output_shape.get("structure", ""),
            "object_bucket": output_shape.get("object_bucket", ""),
            "stream_bucket": output_shape.get("stream_bucket", ""),
            "page_bucket": output_shape.get("page_bucket", ""),
            "has_xref": output_shape.get("has_xref", False),
            "has_trailer": output_shape.get("has_trailer", False),
            "has_eof": output_shape.get("has_eof", False),
        },
        "failure": {
            "kind": failure_shape.get("kind", ""),
            "sanitizer": failure_shape.get("sanitizer", ""),
            "location": failure_shape.get("location", ""),
            "top_functions": failure_shape.get("top_functions", []),
        },
    }


def path_depth_score(path_shape: dict[str, Any]) -> int:
    score = 0
    if path_shape.get("cupstestppd_ok"):
        score += 1
    if path_shape.get("filter_chain"):
        score += 1
    if path_shape.get("reached_expected_filter"):
        score += 2
    states = set(path_shape.get("stderr_states", []))
    stage_weights = {
        "imagetops": 1,
        "imagetoraster": 1,
        "imagetopdf": 1,
        "before-scaling": 2,
        "image-colorspace": 2,
        "cupswidth": 2,
        "cupsheight": 2,
        "cupsbytesperline": 2,
        "formatting-page": 3,
        "job-completed": 4,
    }
    score += sum(stage_weights.get(state, 1) for state in states)
    if path_shape.get("return_class") == "zero":
        score += 2
    if path_shape.get("stdout_size") not in {"missing", "zero"}:
        score += 1
    return score


def output_depth_score(output_shape: dict[str, Any]) -> int:
    fmt = str(output_shape.get("format", ""))
    if fmt in {"", "empty", "missing"}:
        return 0
    score = 1
    if fmt == "pdf":
        score += 4
        score += _bucket_score(str(output_shape.get("object_bucket", "0")))
        score += _bucket_score(str(output_shape.get("stream_bucket", "0")))
        score += 2 * _bucket_score(str(output_shape.get("page_bucket", "0")))
        if output_shape.get("has_xref"):
            score += 1
        if output_shape.get("has_trailer"):
            score += 1
        if output_shape.get("has_eof"):
            score += 1
    elif fmt == "postscript":
        score += 3
        score += _bucket_score(str(output_shape.get("page_bucket", "0")))
        score += _bucket_score(str(output_shape.get("showpage_bucket", "0")))
    elif fmt in {"cups-raster", "pwg-raster"}:
        score += 4
        if output_shape.get("validity") == "header-like":
            score += 2
        score += _bucket_score(str(output_shape.get("height_bucket", "0")))
    elif fmt in {"png", "pnm"}:
        score += 2
    if output_shape.get("size_bucket") not in {"", "zero", "lt64"}:
        score += 1
    return score


def combined_depth_score(shape_bundle: dict[str, Any]) -> int:
    path_shape = shape_bundle.get("path_shape") if isinstance(shape_bundle.get("path_shape"), dict) else {}
    output_shape = shape_bundle.get("output_shape") if isinstance(shape_bundle.get("output_shape"), dict) else {}
    return path_depth_score(path_shape) + output_depth_score(output_shape)


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def parse_ppd_text(text: str) -> dict[str, Any]:
    filters = _parse_ppd_filters(text)
    page_name, page_width, page_height = _parse_page_size(text)
    x_res, y_res = _parse_resolution(text)
    color_model = _parse_default_value(text, "ColorModel")
    return {
        "kind": "ppd" if text else "missing",
        "line_bucket": _count_bucket(text.count("\n")),
        "filter_chain": filters,
        "filter_family": [_filter_family(item) for item in filters],
        "default_page_size": page_name,
        "page_class": _page_class(page_width, page_height),
        "page_orientation": _orientation(page_width, page_height),
        "default_resolution": _resolution_label(x_res, y_res),
        "resolution_class": _resolution_class(x_res, y_res),
        "default_color_model": color_model,
        "has_cups_filter": bool(filters),
    }


def parse_job_options(options: str) -> dict[str, Any]:
    if not options:
        return {"kind": "empty", "keys": []}
    try:
        parts = shlex.split(options)
        parse_state = "ok"
    except ValueError:
        parts = options.split()
        parse_state = "error"
    values: dict[str, Any] = {
        "kind": "cups-options",
        "keys": [],
        "parse_state": parse_state,
        "option_bucket": _count_bucket(len(parts)),
    }
    keys: list[str] = []
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, "true"
        key = key.strip()
        if not key:
            continue
        if key not in keys:
            keys.append(key)
        values[key] = _normalize_option_value(value)
    values["keys"] = keys
    return values


def parse_document_bytes(data: bytes) -> dict[str, Any]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png_shape(data)
    if len(data) >= 2 and data[:1] == b"P" and data[1:2] in {b"1", b"2", b"3", b"4", b"5", b"6"}:
        return _pnm_shape(data)
    if data.startswith(b"%PDF-"):
        return {
            "format": "pdf",
            "size_bucket": _size_bucket(len(data)),
            "structure": f"objects:{_count_bucket(data.count(b' obj'))}|streams:{_count_bucket(data.count(b'stream'))}",
            "validity": "container-like",
        }
    if data.startswith(b"%!PS"):
        return {
            "format": "postscript",
            "size_bucket": _size_bucket(len(data)),
            "structure": f"showpage:{_count_bucket(data.count(b'showpage'))}|lines:{_count_bucket(data.count(bytes([10])))}",
            "validity": "container-like",
        }
    if data.startswith(b"#CUPS-COMMAND"):
        return {
            "format": "cups-command",
            "size_bucket": _size_bucket(len(data)),
            "structure": f"lines:{_count_bucket(data.count(bytes([10])))}",
            "validity": "container-like",
        }
    sync = data[:4].decode("latin1", errors="replace")
    if sync in {"3SaR", "2SaR"}:
        return _raster_shape(data, sync)
    if not data:
        return {"format": "empty", "size_bucket": "zero", "structure": "empty", "validity": "empty"}
    if data.startswith(b"%") or data[:64].isascii():
        return {
            "format": "text-like",
            "size_bucket": _size_bucket(len(data)),
            "structure": f"lines:{_count_bucket(data.count(bytes([10])))}",
            "validity": "text",
        }
    return {
        "format": "binary",
        "size_bucket": _size_bucket(len(data)),
        "structure": f"sync:{sync}",
        "validity": "opaque",
    }


def parse_output_bytes(data: bytes) -> dict[str, Any]:
    if not data:
        return {
            "format": "empty",
            "size_bucket": "zero",
            "structure": "empty",
            "validity": "empty",
        }
    prefix = data[:2048]
    if data.startswith(b"%PDF-") or b"%PDF-" in prefix:
        return _pdf_output_shape(data)
    if data.startswith(b"%!PS") or b"%%Pages:" in prefix or b"showpage" in prefix:
        return _postscript_output_shape(data)
    sync = data[:4].decode("latin1", errors="replace")
    if sync in {"3SaR", "2SaR"}:
        shape = _raster_shape(data, sync)
        shape["source"] = "output"
        return shape
    if data.startswith(b"\x89PNG\r\n\x1a\n") or (
        len(data) >= 2 and data[:1] == b"P" and data[1:2] in {b"1", b"2", b"3", b"4", b"5", b"6"}
    ):
        shape = parse_document_bytes(data)
        shape["source"] = "output"
        return shape
    if prefix.lstrip().startswith(b"%"):
        return {
            "format": "text-percent",
            "size_bucket": _size_bucket(len(data)),
            "structure": f"lines:{_count_bucket(data.count(bytes([10])))}",
            "validity": "text",
        }
    return {
        "format": "binary",
        "size_bucket": _size_bucket(len(data)),
        "structure": f"sync:{sync}",
        "validity": "opaque",
    }


def parse_path_shape(result: Any, stderr_text: str) -> dict[str, Any]:
    filters = [str(item) for item in _get(result, "filters", [])]
    return {
        "target_family": _target_family(str(_get(result, "target_id", ""))),
        "filter_chain": [_filter_family(item) for item in filters],
        "filter_count": _count_bucket(len(filters)),
        "reached_expected_filter": bool(_get(result, "reached_expected_filter", False)),
        "cupstestppd_ok": bool(_get(result, "cupstestppd_ok", False)),
        "return_class": _return_class(_get(result, "returncode", None)),
        "timed_out": bool(_get(result, "timed_out", False)),
        "stderr_states": _stderr_state_tokens(stderr_text),
        "stdout_size": _file_size_bucket(_get(result, "stdout_path", "")),
    }


def parse_failure_shape(result: Any, stderr_text: str) -> dict[str, Any]:
    if not bool(_get(result, "crashed", False)):
        return {
            "kind": "timeout" if bool(_get(result, "timed_out", False)) else "none",
            "sanitizer": "",
            "location": "",
            "top_functions": [],
        }
    summary = _asan_summary(stderr_text)
    sanitizer = _asan_kind(summary)
    top_frames = _top_frames(stderr_text)
    return {
        "kind": "asan" if sanitizer else "signal-or-returncode",
        "sanitizer": sanitizer,
        "location": _failure_location(summary, top_frames),
        "access": _access_class(stderr_text),
        "address": _address_class(stderr_text),
        "top_functions": [frame.get("function", "") for frame in top_frames[:3] if frame.get("function")],
        "top_locations": [frame.get("location", "") for frame in top_frames[:3] if frame.get("location")],
        "summary": _normalize_summary(summary),
        "return_class": _return_class(_get(result, "returncode", None)),
    }


def _semantic_input_shape(
    *,
    target_id: str,
    ppd_kind: str,
    document_kind: str,
    input_mime: str,
    output_mime: str,
    expected_filters: list[str],
    ppd_shape: dict[str, Any],
    document_shape: dict[str, Any],
    job_options_shape: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "target": {
            "id": target_id,
            "family": _target_family(target_id),
        },
        "generator": {
            "ppd_kind": ppd_kind,
            "document_kind": document_kind,
        },
        "ppd": ppd_shape,
        "document": document_shape,
        "job_options": job_options_shape or {"kind": "empty", "keys": []},
    }


def _labels_for_semantic_input(semantic: dict[str, Any]) -> dict[str, str]:
    ppd = semantic.get("ppd", {})
    document = semantic.get("document", {})
    job_options = semantic.get("job_options", {})
    filters = ppd.get("filter_family", []) if isinstance(ppd, dict) else []
    return {
        "doc-format": str(document.get("format", "")),
        "doc-image-class": str(document.get("image_class", "")),
        "doc-structure": str(document.get("structure", ""))[:80],
        "ppd-page-class": str(ppd.get("page_class", "")),
        "ppd-resolution-class": str(ppd.get("resolution_class", "")),
        "ppd-filter": "+".join(filters[:4]),
        "job-option-keys": "+".join(job_options.get("keys", [])[:8]) if isinstance(job_options, dict) else "",
        "job-option-color": str(job_options.get("ColorModel", "")) if isinstance(job_options, dict) else "",
        "job-option-page": str(job_options.get("PageSize", "")) if isinstance(job_options, dict) else "",
        "job-option-resolution": str(job_options.get("Resolution", "")) if isinstance(job_options, dict) else "",
    }


def _labels_for_path(path_shape: dict[str, Any]) -> dict[str, str]:
    return {
        "path-filter": "+".join(path_shape.get("filter_chain", [])[:4]),
        "path-return": str(path_shape.get("return_class", "")),
        "path-reached": str(path_shape.get("reached_expected_filter", False)).lower(),
        "path-stage": _deepest_path_stage(path_shape),
    }


def _labels_for_failure(failure_shape: dict[str, Any]) -> dict[str, str]:
    return {
        "failure-kind": str(failure_shape.get("kind", "")),
        "failure-sanitizer": str(failure_shape.get("sanitizer", "")),
        "failure-location": str(failure_shape.get("location", ""))[:80],
    }


def _labels_for_output(output_shape: dict[str, Any]) -> dict[str, str]:
    return {
        "output-format": str(output_shape.get("format", "")),
        "output-size": str(output_shape.get("size_bucket", "")),
        "output-validity": str(output_shape.get("validity", "")),
        "output-structure": str(output_shape.get("structure", ""))[:80],
    }


def _normalize_option_value(value: str) -> str:
    value = str(value).strip()
    if len(value) <= 48:
        return value
    return value[:48]


def _parse_ppd_filters(text: str) -> list[str]:
    filters: list[str] = []
    for match in re.finditer(r'^\*cupsFilter2?\s*:\s*"([^"]+)"', text, flags=re.MULTILINE):
        fields = match.group(1).split()
        if fields:
            filters.append(fields[-1])
    return filters


def _parse_page_size(text: str) -> tuple[str, int | None, int | None]:
    default = _parse_default_value(text, "PageSize")
    width = None
    height = None
    if default:
        pattern = r"^\*PageSize\s+" + re.escape(default) + r'\b[^\n"]*:\s*"[^"]*?/PageSize\s*\[\s*([0-9.]+)\s+([0-9.]+)\s*\]'
        match = re.search(pattern, text, flags=re.MULTILINE)
        if match:
            width = _safe_float_to_int(match.group(1))
            height = _safe_float_to_int(match.group(2))
    if width is None or height is None:
        match = re.search(r"/PageSize\s*\[\s*([0-9.]+)\s+([0-9.]+)\s*\]", text)
        if match:
            width = _safe_float_to_int(match.group(1))
            height = _safe_float_to_int(match.group(2))
    return default, width, height


def _parse_resolution(text: str) -> tuple[int | None, int | None]:
    value = _parse_default_value(text, "Resolution")
    match = re.search(r"(\d+)\s*x\s*(\d+)\s*dpi", value or "", flags=re.IGNORECASE)
    if match:
        return int(match.group(1)), int(match.group(2))
    match = re.search(r"HWResolution\s*\[\s*(\d+)\s+(\d+)\s*\]", text)
    if match:
        return int(match.group(1)), int(match.group(2))
    return None, None


def _parse_default_value(text: str, keyword: str) -> str:
    match = re.search(r"^\*Default" + re.escape(keyword) + r"\s*:\s*([^\s]+)", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _png_shape(data: bytes) -> dict[str, Any]:
    chunks: list[str] = []
    crc_state = "ok"
    width = height = bit_depth = color_type = interlace = None
    idat_bytes = 0
    pos = 8
    truncated = False
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        raw_type = data[pos + 4 : pos + 8]
        chunk_type = raw_type.decode("latin1", errors="replace")
        payload_start = pos + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if crc_end > len(data):
            truncated = True
            crc_state = "truncated"
            chunks.append(chunk_type)
            break
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack(">I", data[payload_end:crc_end])[0]
        actual_crc = zlib.crc32(raw_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc and crc_state == "ok":
            crc_state = "bad"
        chunks.append(chunk_type)
        if chunk_type == "IHDR" and len(payload) >= 13:
            width, height = struct.unpack(">II", payload[:8])
            bit_depth = payload[8]
            color_type = payload[9]
            interlace = payload[12]
        if chunk_type == "IDAT":
            idat_bytes += length
        pos = crc_end
        if chunk_type == "IEND":
            break
    channels = _png_channels(color_type)
    row_bytes = _row_bytes(width, bit_depth, channels)
    return {
        "format": "png",
        "size_bucket": _size_bucket(len(data)),
        "validity": "truncated" if truncated else f"crc:{crc_state}",
        "width_bucket": _dimension_bucket(width),
        "height_bucket": _dimension_bucket(height),
        "image_class": _image_class(width, height),
        "bit_depth": bit_depth,
        "color_type": color_type,
        "channels": channels,
        "interlace": interlace,
        "row_mod4": None if row_bytes is None else row_bytes % 4,
        "structure": "+".join(chunks[:8]),
        "has_plte": "PLTE" in chunks,
        "has_trns": "tRNS" in chunks,
        "idat_bucket": _size_bucket(idat_bytes),
    }


def _pnm_shape(data: bytes) -> dict[str, Any]:
    tokens: list[bytes] = []
    for raw_line in data.splitlines():
        line = raw_line.split(b"#", 1)[0].strip()
        if not line:
            continue
        tokens.extend(line.split())
        if len(tokens) >= 4:
            break
    magic = tokens[0].decode("ascii", errors="replace") if tokens else "P?"
    width = _safe_int_token(tokens[1]) if len(tokens) > 1 else None
    height = _safe_int_token(tokens[2]) if len(tokens) > 2 else None
    maxval = _safe_int_token(tokens[3]) if len(tokens) > 3 and magic not in {"P1", "P4"} else None
    return {
        "format": "pnm",
        "size_bucket": _size_bucket(len(data)),
        "validity": "header-like" if width and height else "short",
        "magic": magic,
        "width_bucket": _dimension_bucket(width),
        "height_bucket": _dimension_bucket(height),
        "image_class": _image_class(width, height),
        "maxval_class": _maxval_class(maxval),
        "structure": f"{magic}|max:{_maxval_class(maxval)}",
    }


def _raster_shape(data: bytes, sync: str) -> dict[str, Any]:
    if len(data) < 4 + 424:
        return {
            "format": "cups-raster" if sync == "3SaR" else "pwg-raster",
            "size_bucket": _size_bucket(len(data)),
            "structure": "short-header",
            "validity": "short",
        }
    header = data[4 : 4 + 1796]
    width = _u32(header, 372)
    height = _u32(header, 376)
    bpp = _u32(header, 388)
    bpl = _u32(header, 392)
    color_space = _u32(header, 400)
    compression = _u32(header, 404)
    row_count = _u32(header, 408)
    format_name = "cups-raster" if sync == "3SaR" else "pwg-raster"
    return {
        "format": format_name,
        "size_bucket": _size_bucket(len(data)),
        "validity": "header-like",
        "width_bucket": _dimension_bucket(width),
        "height_bucket": _dimension_bucket(height),
        "image_class": _image_class(width, height),
        "bpp": bpp,
        "bpl_bucket": _count_bucket(bpl),
        "row_mod4": bpl % 4,
        "color_space": color_space,
        "compression": compression,
        "row_count_class": _count_bucket(row_count),
        "structure": (
            f"sync:{sync}|size:{_size_bucket(len(data))}|w:{_dimension_bucket(width)}|"
            f"h:{_dimension_bucket(height)}|class:{_image_class(width, height)}|"
            f"bpp:{bpp}|bpl:{_count_bucket(bpl)}|row:{_count_bucket(row_count)}|"
            f"color:{color_space}|comp:{compression}|mod4:{bpl % 4}"
        ),
    }


def _pdf_output_shape(data: bytes) -> dict[str, Any]:
    header = _pdf_header(data)
    object_count = len(re.findall(rb"\b\d+\s+\d+\s+obj\b", data))
    stream_count = data.count(b"\nstream") + data.count(b"\r\nstream")
    page_count = len(re.findall(rb"/Type\s*/Page\b", data))
    xobject_count = len(re.findall(rb"/Subtype\s*/Image\b", data))
    filter_names = sorted({item.decode("latin1", errors="replace") for item in re.findall(rb"/Filter\s*/([A-Za-z0-9]+)", data)})
    return {
        "format": "pdf",
        "size_bucket": _size_bucket(len(data)),
        "validity": _pdf_validity(data, header, object_count),
        "version": header,
        "object_bucket": _count_bucket(object_count),
        "stream_bucket": _count_bucket(stream_count),
        "page_bucket": _count_bucket(page_count),
        "image_xobject_bucket": _count_bucket(xobject_count),
        "filter_names": filter_names[:6],
        "has_xref": b"xref" in data[-4096:] or b"/XRef" in data,
        "has_trailer": b"trailer" in data[-4096:] or b"/Root" in data,
        "has_eof": b"%%EOF" in data[-1024:],
        "structure": (
            f"pdf:{header}|size:{_size_bucket(len(data))}|obj:{_count_bucket(object_count)}|"
            f"stream:{_count_bucket(stream_count)}|page:{_count_bucket(page_count)}|"
            f"image:{_count_bucket(xobject_count)}|filter:{_filter_label(filter_names)}|"
            f"xref:{int(b'xref' in data[-4096:] or b'/XRef' in data)}|"
            f"eof:{int(b'%%EOF' in data[-1024:])}"
        ),
    }


def _postscript_output_shape(data: bytes) -> dict[str, Any]:
    pages_match = re.search(rb"%%Pages:\s*(\d+)", data[:8192])
    declared_pages = int(pages_match.group(1)) if pages_match else 0
    showpage_count = data.count(b"showpage")
    image_count = data.count(b"image") + data.count(b"imagemask")
    return {
        "format": "postscript",
        "size_bucket": _size_bucket(len(data)),
        "validity": "document-like" if data.startswith(b"%!PS") else "body-like",
        "page_bucket": _count_bucket(declared_pages),
        "showpage_bucket": _count_bucket(showpage_count),
        "image_bucket": _count_bucket(image_count),
        "has_bounding_box": b"%%BoundingBox:" in data[:8192],
        "has_pages": bool(pages_match),
        "has_eof": b"%%EOF" in data[-1024:],
        "structure": (
            f"ps|size:{_size_bucket(len(data))}|pages:{_count_bucket(declared_pages)}|"
            f"showpage:{_count_bucket(showpage_count)}|image:{_count_bucket(image_count)}|"
            f"bbox:{int(b'%%BoundingBox:' in data[:8192])}|eof:{int(b'%%EOF' in data[-1024:])}"
        ),
    }


def _pdf_header(data: bytes) -> str:
    match = re.search(rb"%PDF-(\d+\.\d+)", data[:2048])
    if not match:
        return "unknown"
    return match.group(1).decode("ascii", errors="replace")


def _pdf_validity(data: bytes, header: str, object_count: int) -> str:
    traits = []
    traits.append("header" if header != "unknown" else "no-header")
    traits.append("objects" if object_count else "no-objects")
    if b"xref" in data[-4096:] or b"/XRef" in data:
        traits.append("xref")
    if b"trailer" in data[-4096:] or b"/Root" in data:
        traits.append("trailer")
    if b"%%EOF" in data[-1024:]:
        traits.append("eof")
    return "+".join(traits)


def _filter_label(filter_names: list[str]) -> str:
    if not filter_names:
        return "none"
    return "+".join(filter_names[:3])


def _stderr_state_tokens(stderr_text: str) -> list[str]:
    markers = {
        "cffilterimagetopdf:": "imagetopdf",
        "cffilterimagetoraster:": "imagetoraster",
        "ppdfilterimagetops": "imagetops",
        "before scaling:": "before-scaling",
        "using portrait orientation": "portrait",
        "using landscape orientation": "landscape",
        "formatting page": "formatting-page",
        "cupswidth =": "cupswidth",
        "cupsheight =": "cupsheight",
        "cupsbytesperline =": "cupsbytesperline",
        "img->colorspace =": "image-colorspace",
    }
    tokens: set[str] = set()
    for line in stderr_text.splitlines():
        lowered = line.strip().lower()
        for marker, token in markers.items():
            if marker in lowered:
                tokens.add(token)
        if "addresssanitizer" in lowered:
            tokens.add("asan")
        if "job completed" in lowered:
            tokens.add("job-completed")
    return sorted(tokens)


def _pipeline_label(path_shape: dict[str, Any], output_shape: dict[str, Any] | None = None) -> str:
    output_shape = output_shape or {}
    filters = "+".join(path_shape.get("filter_chain", [])[:3]) or "no-filter"
    reached = "reached" if path_shape.get("reached_expected_filter") else "not-reached"
    return_class = path_shape.get("return_class") or "unknown"
    output_format = output_shape.get("format", "") or "no-output"
    depth = path_depth_score(path_shape) + output_depth_score(output_shape)
    return f"{filters}|{reached}|{return_class}|output:{output_format}|depth:{_depth_bucket(depth)}"


def _deepest_path_stage(path_shape: dict[str, Any]) -> str:
    states = set(path_shape.get("stderr_states", []))
    ordered = [
        "job-completed",
        "formatting-page",
        "cupsbytesperline",
        "cupsheight",
        "cupswidth",
        "image-colorspace",
        "before-scaling",
        "imagetopdf",
        "imagetoraster",
        "imagetops",
        "asan",
    ]
    for state in ordered:
        if state in states:
            return state
    return "none"


def _depth_bucket(score: int) -> str:
    if score <= 0:
        return "0"
    if score <= 2:
        return "1-2"
    if score <= 5:
        return "3-5"
    if score <= 9:
        return "6-9"
    if score <= 14:
        return "10-14"
    return "15+"


def _asan_summary(stderr_text: str) -> str:
    for line in stderr_text.splitlines():
        if line.startswith("SUMMARY: AddressSanitizer:"):
            return " ".join(line.split())
    return ""


def _asan_kind(summary: str) -> str:
    match = re.search(r"SUMMARY:\s+AddressSanitizer:\s+(\S+)", summary)
    return match.group(1) if match else ""


def _top_frames(stderr_text: str) -> list[dict[str, str]]:
    frames: list[dict[str, str]] = []
    for line in stderr_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        match = re.search(r"^#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(.+?)(?:\s+(\S+:\d+)(?::\d+)?)?$", stripped)
        if not match:
            continue
        function = _normalize_function(match.group(1))
        location = _normalize_location(match.group(2) or "")
        frames.append({"function": function, "location": location})
        if len(frames) >= 5:
            break
    return frames


def _failure_location(summary: str, frames: list[dict[str, str]]) -> str:
    if summary:
        match = re.search(r"\s(\S+:\d+)\s+in\s+(\S+)", summary)
        if match:
            return f"{_normalize_location(match.group(1))}:in:{_normalize_function(match.group(2))}"
        match = re.search(r"\sin\s+(\S+)", summary)
        if match:
            return f"in:{_normalize_function(match.group(1))}"
    if frames:
        location = frames[0].get("location", "")
        function = frames[0].get("function", "")
        return f"{location}:in:{function}" if location else f"in:{function}"
    return ""


def _normalize_summary(summary: str) -> str:
    summary = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", summary)
    summary = re.sub(r"==\d+==", "==PID==", summary)
    return " ".join(summary.split())


def _access_class(stderr_text: str) -> str:
    match = re.search(r"\b(READ|WRITE) of size (\d+)", stderr_text)
    if match:
        return f"{match.group(1).lower()}:{_count_bucket(int(match.group(2)))}"
    return ""


def _address_class(stderr_text: str) -> str:
    lowered = stderr_text.lower()
    if "unknown address" in lowered:
        return "unknown"
    if "zero page" in lowered or "null pointer" in lowered:
        return "null-ish"
    if "wild pointer" in lowered:
        return "wild"
    return ""


def _parse_default_number(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float_to_int(value: str) -> int | None:
    try:
        return int(float(value))
    except ValueError:
        return None


def _safe_int_token(value: bytes) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace") if path else ""
    except OSError:
        return ""


def _read_bytes(path: str) -> bytes:
    try:
        return Path(path).read_bytes() if path else b""
    except OSError:
        return b""


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _file_size_bucket(path: str) -> str:
    try:
        return _size_bucket(Path(path).stat().st_size) if path else "missing"
    except OSError:
        return "missing"


def _return_class(returncode: Any) -> str:
    code = _parse_default_number(str(returncode)) if returncode is not None else None
    if code is None:
        return "none"
    if code == 0:
        return "zero"
    if code < 0:
        return "signal"
    if code in {86, 134, 139}:
        return f"crash-code:{code}"
    return "nonzero"


def _target_family(target_id: str) -> str:
    for suffix in ("_coverage", "_general", "_explore", "_structural", "_feedback"):
        if target_id.endswith(suffix):
            return target_id.removesuffix(suffix)
    return target_id


def _filter_family(name: str) -> str:
    value = Path(name).name if "/" in name else name
    return re.sub(r"[^A-Za-z0-9_.+-]", "_", value)


def _page_class(width: int | None, height: int | None) -> str:
    if not width or not height:
        return "unknown"
    area = width * height
    if area <= 144 * 144:
        return "tiny"
    if 500 <= width <= 700 and 700 <= height <= 900:
        return "letterish"
    if width > 1000 or height > 1000:
        return "large"
    return "custom"


def _orientation(width: int | None, height: int | None) -> str:
    if not width or not height:
        return "unknown"
    if width == height:
        return "square"
    return "landscape" if width > height else "portrait"


def _resolution_label(x_res: int | None, y_res: int | None) -> str:
    if not x_res or not y_res:
        return "unknown"
    return f"{x_res}x{y_res}"


def _resolution_class(x_res: int | None, y_res: int | None) -> str:
    if not x_res or not y_res:
        return "unknown"
    value = max(x_res, y_res)
    if value <= 2:
        return "unit-or-near-zero"
    if value < 150:
        return "low"
    if value <= 720:
        return "normal"
    if value <= 2400:
        return "high"
    return "extreme"


def _image_class(width: int | None, height: int | None) -> str:
    if not width or not height:
        return "unknown"
    area = width * height
    traits = []
    if width == 1 or height == 1:
        traits.append("line")
    elif width <= 4 and height <= 4:
        traits.append("tiny")
    elif area <= 256:
        traits.append("small")
    elif area <= 16384:
        traits.append("medium")
    else:
        traits.append("large")
    if width % 2 or height % 2:
        traits.append("odd")
    if width in {1, 2, 3, 7, 15, 31, 63, 127, 255, 511, 1023}:
        traits.append("width-boundary")
    return "+".join(traits)


def _png_channels(color_type: int | None) -> int | None:
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)


def _row_bytes(width: int | None, bit_depth: int | None, channels: int | None) -> int | None:
    if not width or bit_depth is None or channels is None:
        return None
    return (width * bit_depth * channels + 7) // 8


def _dimension_bucket(value: int | None) -> str:
    if value is None:
        return "unknown"
    if value <= 1:
        return "1"
    if value <= 4:
        return "2-4"
    if value <= 16:
        return "5-16"
    if value <= 64:
        return "17-64"
    if value <= 256:
        return "65-256"
    if value <= 1024:
        return "257-1024"
    return "gt1024"


def _size_bucket(size: int) -> str:
    if size <= 0:
        return "zero"
    if size < 64:
        return "lt64"
    if size < 512:
        return "64-512"
    if size < 4096:
        return "512-4k"
    if size < 65536:
        return "4k-64k"
    if size < 1024 * 1024:
        return "64k-1m"
    return "ge1m"


def _count_bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 4:
        return "2-4"
    if value <= 16:
        return "5-16"
    if value <= 64:
        return "17-64"
    if value <= 256:
        return "65-256"
    return "gt256"


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


def _maxval_class(value: int | None) -> str:
    if value is None:
        return "none"
    if value <= 1:
        return "bitmap"
    if value <= 255:
        return "byte"
    return "wide"


def _u32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]


def _normalize_function(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    value = re.sub(r"\(.*\)$", "", value)
    return value[:96]


def _normalize_location(value: str) -> str:
    if not value:
        return ""
    return value.replace("/data/pre-gsoc/", "").replace("/usr/include/", "usr/include/")
