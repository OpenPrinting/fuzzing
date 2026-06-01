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
    records = _read_timeline(root / "timeline.jsonl")
    crash_records = [record for record in records if record.get("crashed")]
    timeout_records = [record for record in records if record.get("timed_out")]
    clusters: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    infra_excluded = 0

    for record in records:
        if not record.get("crashed"):
            continue
        if record.get("timed_out") and not include_timeouts:
            continue

        stderr_text = _read_stderr(record)
        if exclude_infra and _is_infra_noise(record, stderr_text):
            infra_excluded += 1
            continue

        target_id = str(record.get("target_id", "unknown"))
        oracle = str(record.get("oracle") or "none")
        signature = _signature(record, stderr_text)
        clusters.setdefault((target_id, oracle, signature), []).append(record)

    cluster_rows = [
        _make_cluster(target_id, oracle, signature, items)
        for (target_id, oracle, signature), items in clusters.items()
    ]
    cluster_rows.sort(key=lambda row: (-row.count, row.target_id, row.signature))
    summary = CrashDedupSummary(
        run_dir=str(root),
        total_records=len(records),
        crash_records=len(crash_records),
        timeout_records=len(timeout_records),
        infra_excluded_records=infra_excluded,
        unique_crashes=len(cluster_rows),
        clusters=cluster_rows,
    )

    json_path = Path(output_json) if output_json else root / "crash_dedup.json"
    md_path = Path(output_md) if output_md else root / "crash_dedup.md"
    json_path.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_format_markdown(summary), encoding="utf-8")
    return summary


def _read_timeline(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
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
            return _normalize_line(line)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#0"):
            return _normalize_line(stripped)
    for line in lines:
        lowered = line.lower()
        if "crashed on signal" in lowered:
            return _normalize_line(line.strip())
    return f"returncode={record.get('returncode')} oracle={record.get('oracle') or 'none'}"


def _normalize_line(line: str) -> str:
    line = ADDRESS_RE.sub("0xADDR", line)
    line = PID_RE.sub("==PID==", line)
    line = BUILD_ID_RE.sub("(BuildId: BUILDID)", line)
    return " ".join(line.split())


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
