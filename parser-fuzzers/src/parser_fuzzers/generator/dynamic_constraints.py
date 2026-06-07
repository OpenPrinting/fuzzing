from __future__ import annotations

import csv
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from parser_fuzzers.source_constraints import OPTION_TOKENS


MAGIC_TOKENS = {"2SaR", "3SaR", "RaS2", "%PDF-", "%!PS"}
MIME_RE = re.compile(r"application/[A-Za-z0-9.+_-]+(?:/[A-Za-z0-9.+_-]+)?")


@dataclass(frozen=True)
class DynamicCompareRecord:
    trace_path: str
    pid: str
    pc: str
    op: str
    ret: int
    length: int
    a_hex: str
    b_hex: str
    a_ascii: str
    b_ascii: str
    tokens: tuple[str, ...]


def build_dynamic_compare_profile(
    run_dir: str | Path,
    *,
    max_records: int = 2000,
) -> dict[str, Any]:
    root = Path(run_dir)
    records: list[DynamicCompareRecord] = []
    op_counts: Counter[str] = Counter()
    token_counts: Counter[str] = Counter()
    pc_counts: Counter[str] = Counter()
    total = 0
    equal = 0
    nonzero = 0
    trace_files = 0

    for trace_path in sorted(root.rglob("compare_trace.tsv")):
        trace_files += 1
        for record in _read_trace(trace_path):
            total += 1
            op_counts[record.op] += 1
            pc_counts[record.pc] += 1
            if record.ret == 0:
                equal += 1
            else:
                nonzero += 1
            for token in record.tokens:
                token_counts[token] += 1
            if len(records) < max_records:
                records.append(record)

    return {
        "schema_version": "dynamic-compare-hints-v1",
        "run_dir": str(root),
        "summary": {
            "trace_files": trace_files,
            "compare_records": total,
            "records": len(records),
            "records_truncated": len(records) >= max_records,
            "equal_compares": equal,
            "nonzero_compares": nonzero,
            "op_counts": dict(sorted(op_counts.items())),
            "top_pcs": dict(pc_counts.most_common(32)),
        },
        "tokens": dict(token_counts.most_common(128)),
        "ppd_options": {
            token: count for token, count in token_counts.most_common(128) if token in OPTION_TOKENS
        },
        "magic_tokens": {
            token: count for token, count in token_counts.most_common(128) if token in MAGIC_TOKENS
        },
        "records": [asdict(record) for record in records],
    }


def write_dynamic_compare_profile(profile: dict[str, Any], output_path: str | Path) -> None:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_trace(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            for row in reader:
                record = _record_from_row(path, row)
                if record is not None:
                    yield record
    except OSError:
        return


def _record_from_row(path: Path, row: dict[str, str]) -> DynamicCompareRecord | None:
    try:
        ret = int(row.get("ret", "0"))
        length = int(row.get("len", "0"))
    except ValueError:
        return None
    a_ascii = row.get("a_ascii", "")
    b_ascii = row.get("b_ascii", "")
    tokens = _tokens_from_compare(a_ascii, b_ascii)
    return DynamicCompareRecord(
        trace_path=str(path),
        pid=row.get("pid", ""),
        pc=row.get("pc", ""),
        op=row.get("op", ""),
        ret=ret,
        length=length,
        a_hex=row.get("a_hex", ""),
        b_hex=row.get("b_hex", ""),
        a_ascii=a_ascii,
        b_ascii=b_ascii,
        tokens=tokens,
    )


def _tokens_from_compare(a_ascii: str, b_ascii: str) -> tuple[str, ...]:
    tokens = set()
    for side in (a_ascii, b_ascii):
        compact = side.strip()
        if not compact:
            continue
        for token in OPTION_TOKENS | MAGIC_TOKENS:
            if token and token in compact:
                tokens.add(token)
        for match in MIME_RE.finditer(compact):
            tokens.add(match.group(0).rstrip("."))
    return tuple(sorted(tokens))
