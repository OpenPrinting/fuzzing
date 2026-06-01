from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


EXPECTED_EXPERIMENT_NAMES = {
    "vanilla",
    "dictionary",
    "dictionary+cmplog",
    "dictionary+grammar",
    "dictionary+grammar+smt",
}


@dataclass(frozen=True)
class ValidationIssue:
    level: str
    path: str
    message: str


def load_yaml(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def validate_all(
    configs_dir: str | Path,
) -> list[ValidationIssue]:
    return validate_config_dir(configs_dir)


def validate_config_dir(configs_dir: str | Path) -> list[ValidationIssue]:
    root = Path(configs_dir)
    issues: list[ValidationIssue] = []
    if not root.exists():
        return [ValidationIssue("error", str(root), "config directory does not exist")]

    experiment_path = root / "experiment.yaml"
    targets_path = root / "targets.yaml"
    afl_path = root / "afl.yaml"
    if not experiment_path.exists():
        issues.append(ValidationIssue("error", str(experiment_path), "missing experiment.yaml"))
    else:
        issues.extend(validate_experiment_config(experiment_path))
    if not targets_path.exists():
        issues.append(ValidationIssue("error", str(targets_path), "missing targets.yaml"))
    else:
        issues.extend(validate_targets_config(targets_path))
    if not afl_path.exists():
        issues.append(ValidationIssue("error", str(afl_path), "missing afl.yaml"))
    else:
        issues.extend(validate_afl_config(afl_path))
    return issues


def validate_experiment_config(path: str | Path) -> list[ValidationIssue]:
    config_path = Path(path)
    data = load_yaml(config_path) or {}
    issues: list[ValidationIssue] = []
    configs = data.get("fuzz_configs")
    if not isinstance(configs, list) or not configs:
        return [ValidationIssue("error", str(config_path), "fuzz_configs must be a non-empty list")]
    names = {str(item.get("name")) for item in configs if isinstance(item, dict)}
    missing = sorted(EXPECTED_EXPERIMENT_NAMES - names)
    extra = sorted(names - EXPECTED_EXPERIMENT_NAMES)
    for name in missing:
        issues.append(ValidationIssue("error", str(config_path), f"missing experiment config: {name}"))
    for name in extra:
        issues.append(ValidationIssue("warning", str(config_path), f"unexpected experiment config: {name}"))
    return issues


def validate_targets_config(path: str | Path) -> list[ValidationIssue]:
    config_path = Path(path)
    data = load_yaml(config_path) or {}
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        return [ValidationIssue("error", str(config_path), "targets must be a non-empty list")]
    issues: list[ValidationIssue] = []
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            issues.append(ValidationIssue("error", str(config_path), f"target {index} must be a mapping"))
            continue
        for field in ("id", "name", "components"):
            if field not in target:
                issues.append(ValidationIssue("error", str(config_path), f"target {index} missing {field}"))
    return issues


def validate_afl_config(path: str | Path) -> list[ValidationIssue]:
    config_path = Path(path)
    data = load_yaml(config_path) or {}
    afl = data.get("afl")
    if not isinstance(afl, dict):
        return [ValidationIssue("error", str(config_path), "afl must be a mapping")]
    issues: list[ValidationIssue] = []
    for field in ("fuzzer", "compiler_cc", "compiler_cxx", "input_seed_dir", "work_dir", "output_dir"):
        if not afl.get(field):
            issues.append(ValidationIssue("error", str(config_path), f"afl.{field} must be set"))
    for field in ("timeout_ms", "memory_mb"):
        value = afl.get(field)
        if not isinstance(value, int) or value <= 0:
            issues.append(ValidationIssue("error", str(config_path), f"afl.{field} must be a positive integer"))
    env = afl.get("env", {})
    if env is not None and not isinstance(env, dict):
        issues.append(ValidationIssue("error", str(config_path), "afl.env must be a mapping"))
    return issues
