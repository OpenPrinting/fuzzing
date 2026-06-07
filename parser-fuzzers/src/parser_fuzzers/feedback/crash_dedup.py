from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")
PID_RE = re.compile(r"==\d+==")
BUILD_ID_RE = re.compile(r"\(BuildId: [^)]+\)")


@dataclass(frozen=True)
class CrashCluster:
    signature: str
    target_id: str
    oracle: str
    count: int
    representative_work_dir: str
    representative_command: str
    representative_stderr: str
    sample_work_dirs: list[str]


@dataclass(frozen=True)
class CrashDedupSummary:
    run_dir: str
    total_records: int
    crash_records: int
    timeout_records: int
    infra_excluded_records: int
    unique_crashes: int
    clusters: list[CrashCluster]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def dedup_run(
    run_dir: str | Path,
    *,
    output_json: str | Path | None = None,
    output_md: str | Path | None = None,
    include_timeouts: bool = False,
    exclude_infra: bool = True,
) -> CrashDedupSummary:
    root = Path(run_dir)
    total_records = 0
    crash_records = 0
    timeout_records = 0
    clusters: dict[tuple[str, str, str], dict[str, Any]] = {}
    infra_excluded = 0

    for record in _iter_timeline(root / "timeline.jsonl"):
        total_records += 1
        if record.get("timed_out"):
            timeout_records += 1
        if not record.get("crashed"):
            continue
        crash_records += 1
        if record.get("timed_out") and not include_timeouts:
            continue

        stderr_text = _read_stderr(record)
        if exclude_infra and _is_infra_noise(record, stderr_text):
            infra_excluded += 1
            continue

        target_id = str(record.get("target_id", "unknown"))
        oracle = str(record.get("oracle") or "none")
        signature = _signature(record, stderr_text)
        _add_cluster_record(clusters, (target_id, oracle, signature), record)

    cluster_rows = [
        _make_cluster_from_accumulator(target_id, oracle, signature, accumulator)
        for (target_id, oracle, signature), accumulator in clusters.items()
    ]
    cluster_rows.sort(key=lambda row: (-row.count, row.target_id, row.signature))
    summary = CrashDedupSummary(
        run_dir=str(root),
        total_records=total_records,
        crash_records=crash_records,
        timeout_records=timeout_records,
        infra_excluded_records=infra_excluded,
        unique_crashes=len(cluster_rows),
        clusters=cluster_rows,
    )

    json_path = Path(output_json) if output_json else root / "crash_dedup.json"
    md_path = Path(output_md) if output_md else root / "crash_dedup.md"
    json_path.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_format_markdown(summary), encoding="utf-8")
    return summary


def _iter_timeline(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield json.loads(stripped)


def _read_timeline(path: Path) -> list[dict[str, Any]]:
    records = []
    for record in _iter_timeline(path):
        records.append(record)
    return records


def _read_stderr(record: dict[str, Any]) -> str:
    stderr_path = record.get("stderr_path")
    if stderr_path:
        path = Path(str(stderr_path))
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
    return "\n".join(str(line) for line in record.get("stderr_tail") or [])


def _is_infra_noise(record: dict[str, Any], stderr_text: str) -> bool:
    text = stderr_text.lower()
    oracle = str(record.get("oracle") or "").lower()
    return "asan runtime does not come first" in text or oracle == "infra-asan-runtime-order"


def _signature(record: dict[str, Any], stderr_text: str) -> str:
    return compute_crash_signature(record, stderr_text)


def compute_crash_signature(record: dict[str, Any], stderr_text: str) -> str:
    lines = stderr_text.splitlines()
    for line in lines:
        if line.startswith("SUMMARY: AddressSanitizer:"):
            summary = _normalize_line(line)
            project_frame = _first_actionable_frame(lines)
            if project_frame and _summary_needs_frame_context(summary):
                return f"{summary} | frame:{project_frame}"
            return summary
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#0"):
            return _normalize_line(stripped)
    for line in lines:
        lowered = line.lower()
        if "crashed on signal" in lowered:
            return _normalize_line(line.strip())
    return f"returncode={record.get('returncode')} oracle={record.get('oracle') or 'none'}"


def _summary_needs_frame_context(summary: str) -> bool:
    lowered = summary.lower()
    generic_markers = (
        "/usr/include/",
        "../sysdeps/",
        "/sysdeps/",
        " in __mem",
        " in memset",
        " in memcpy",
        " in memmove",
        " in malloc",
        " in free",
    )
    return any(marker in lowered for marker in generic_markers)


def _first_actionable_frame(lines: list[str]) -> str:
    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith("#"):
            continue
        normalized = _normalize_line(line)
        lowered = normalized.lower()
        if _is_runtime_frame(lowered):
            continue
        return normalized
    return ""


def _is_runtime_frame(lowered_frame: str) -> bool:
    runtime_markers = (
        "/usr/include/",
        "../sysdeps/",
        "/sysdeps/",
        "libsanitizer",
        "asan_",
        " in __libc_",
        " in __mem",
        " in memset ",
        " in memcpy ",
        " in memmove ",
        " in malloc ",
        " in free ",
    )
    return any(marker in lowered_frame for marker in runtime_markers)


def _normalize_line(line: str) -> str:
    line = ADDRESS_RE.sub("0xADDR", line)
    line = PID_RE.sub("==PID==", line)
    line = BUILD_ID_RE.sub("(BuildId: BUILDID)", line)
    return " ".join(line.split())


def _add_cluster_record(
    clusters: dict[tuple[str, str, str], dict[str, Any]],
    key: tuple[str, str, str],
    record: dict[str, Any],
) -> None:
    accumulator = clusters.setdefault(
        key,
        {
            "count": 0,
            "representative": None,
            "sample_work_dirs": [],
        },
    )
    accumulator["count"] += 1
    work_dir = str(record.get("work_dir", ""))
    if work_dir and len(accumulator["sample_work_dirs"]) < 5:
        accumulator["sample_work_dirs"].append(work_dir)
    representative = accumulator["representative"]
    if representative is None or _record_sort_key(record) < _record_sort_key(representative):
        accumulator["representative"] = dict(record)


def _record_sort_key(record: dict[str, Any]) -> tuple[str, int]:
    return (str(record.get("target_id", "")), _safe_int(record.get("case_id", 0)))


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _make_cluster_from_accumulator(
    target_id: str,
    oracle: str,
    signature: str,
    accumulator: dict[str, Any],
) -> CrashCluster:
    representative = accumulator.get("representative") or {}
    return CrashCluster(
        signature=signature,
        target_id=target_id,
        oracle=oracle,
        count=int(accumulator.get("count", 0)),
        representative_work_dir=str(representative.get("work_dir", "")),
        representative_command=str(representative.get("command_line", "")),
        representative_stderr=str(representative.get("stderr_path", "")),
        sample_work_dirs=[str(item) for item in accumulator.get("sample_work_dirs", [])],
    )


def _make_cluster(target_id: str, oracle: str, signature: str, items: list[dict[str, Any]]) -> CrashCluster:
    items.sort(key=lambda item: (str(item.get("target_id", "")), int(item.get("case_id", 0))))
    representative = items[0]
    return CrashCluster(
        signature=signature,
        target_id=target_id,
        oracle=oracle,
        count=len(items),
        representative_work_dir=str(representative.get("work_dir", "")),
        representative_command=str(representative.get("command_line", "")),
        representative_stderr=str(representative.get("stderr_path", "")),
        sample_work_dirs=[str(item.get("work_dir", "")) for item in items[:5]],
    )


def _format_markdown(summary: CrashDedupSummary) -> str:
    lines = [
        "# Crash Dedup",
        "",
        f"Run dir: `{summary.run_dir}`",
        "",
        "## Counts",
        "",
        f"- Total records: {summary.total_records}",
        f"- Crash-classified records: {summary.crash_records}",
        f"- Timeout records: {summary.timeout_records}",
        f"- Infra records excluded: {summary.infra_excluded_records}",
        f"- Unique crash signatures: {summary.unique_crashes}",
        "",
        "## Clusters",
        "",
    ]
    for cluster in summary.clusters:
        lines.extend(
            [
                f"- count={cluster.count} target=`{cluster.target_id}` oracle=`{cluster.oracle}`",
                f"  signature: `{cluster.signature}`",
                f"  representative: `{cluster.representative_work_dir}`",
                f"  stderr: `{cluster.representative_stderr}`",
                f"  cmd: `{cluster.representative_command}`",
            ]
        )
    return "\n".join(lines) + "\n"
