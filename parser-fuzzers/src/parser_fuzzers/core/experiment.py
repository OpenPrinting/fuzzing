from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from parser_fuzzers.validation import load_yaml


@dataclass(frozen=True)
class ExperimentRow:
    id: str
    name: str
    description: str
    dictionary: bool
    cmplog: bool
    grammar: bool
    smt: bool


def load_experiment_rows(config_path: str | Path) -> list[ExperimentRow]:
    data = load_yaml(config_path) or {}
    rows = []
    for item in data.get("fuzz_configs", []):
        rows.append(
            ExperimentRow(
                id=str(item["id"]),
                name=str(item["name"]),
                description=str(item.get("description", "")),
                dictionary=bool(item.get("dictionary", False)),
                cmplog=bool(item.get("cmplog", False)),
                grammar=bool(item.get("grammar", False)),
                smt=bool(item.get("smt", False)),
            )
        )
    return rows


def estimate_cpu_hours(config_count: int, target_count: int, repetitions: int, hours: int) -> int:
    return config_count * target_count * repetitions * hours
