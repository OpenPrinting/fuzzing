from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .experiment import ExperimentRow, load_experiment_rows
from .validation import load_yaml


@dataclass(frozen=True)
class AFLSettings:
    fuzzer: str
    compiler_cc: str
    compiler_cxx: str
    input_seed_dir: str
    smt_corpus_dir: str
    work_dir: str
    output_dir: str
    timeout_ms: int
    memory_mb: int
    cmplog_binary_suffix: str
    custom_mutator_library: str
    env: dict[str, str]


@dataclass(frozen=True)
class TargetConfig:
    id: str
    name: str
    dictionaries: list[str]


@dataclass(frozen=True)
class AFLPlan:
    target_id: str
    config_id: str
    config_name: str
    argv: list[str]
    env: dict[str, str]
    input_dir: str
    output_dir: str
    dictionary: str | None
    cmplog_binary: str | None
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["command"] = shlex.join(self.argv)
        return data


def load_afl_settings(configs_dir: str | Path) -> AFLSettings:
    path = Path(configs_dir) / "afl.yaml"
    data = load_yaml(path) or {}
    afl = data.get("afl", {})
    env = {str(key): str(value) for key, value in (afl.get("env") or {}).items()}
    return AFLSettings(
        fuzzer=str(afl.get("fuzzer", "afl-fuzz")),
        compiler_cc=str(afl.get("compiler_cc", "afl-clang-fast")),
        compiler_cxx=str(afl.get("compiler_cxx", "afl-clang-fast++")),
        input_seed_dir=str(afl.get("input_seed_dir", "seeds/public")),
        smt_corpus_dir=str(afl.get("smt_corpus_dir", "work/corpus/smt")),
        work_dir=str(afl.get("work_dir", "work/afl")),
        output_dir=str(afl.get("output_dir", "work/afl/out")),
        timeout_ms=int(afl.get("timeout_ms", 3000)),
        memory_mb=int(afl.get("memory_mb", 1024)),
        cmplog_binary_suffix=str(afl.get("cmplog_binary_suffix", ".cmplog")),
        custom_mutator_library=str(afl.get("custom_mutator_library", "")),
        env=env,
    )


def load_target_configs(configs_dir: str | Path) -> dict[str, TargetConfig]:
    data = load_yaml(Path(configs_dir) / "targets.yaml") or {}
    targets: dict[str, TargetConfig] = {}
    for item in data.get("targets", []):
        target = TargetConfig(
            id=str(item["id"]),
            name=str(item.get("name", item["id"])),
            dictionaries=[str(path) for path in item.get("dictionaries", [])],
        )
        targets[target.id] = target
    return targets


def resolve_experiment(configs_dir: str | Path, config_ref: str) -> ExperimentRow:
    rows = load_experiment_rows(Path(configs_dir) / "experiment.yaml")
    for row in rows:
        if row.id == config_ref or row.name == config_ref:
            return row
    known = ", ".join(f"{row.id}/{row.name}" for row in rows)
    raise ValueError(f"unknown fuzz config {config_ref!r}; known configs: {known}")


def build_afl_plan(
    root: str | Path,
    configs_dir: str | Path,
    target_id: str,
    config_ref: str,
    binary: str | Path,
) -> AFLPlan:
    root_path = Path(root)
    configs_path = root_path / configs_dir
    settings = load_afl_settings(configs_path)
    targets = load_target_configs(configs_path)
    if target_id not in targets:
        known = ", ".join(sorted(targets))
        raise ValueError(f"unknown target {target_id!r}; known targets: {known}")

    row = resolve_experiment(configs_path, config_ref)
    target = targets[target_id]
    warnings: list[str] = []

    input_dir, smt_count = prepare_input_corpus(root_path, settings, target.id, row)
    output_dir = root_path / settings.output_dir / target.id / row.id
    output_dir.mkdir(parents=True, exist_ok=True)

    dictionary_path: Path | None = None
    if row.dictionary:
        dictionary_path = prepare_dictionary(root_path, settings, target)

    cmplog_binary: Path | None = None
    binary_path = Path(binary)
    if row.cmplog:
        cmplog_binary = Path(str(binary_path) + settings.cmplog_binary_suffix)
        if not cmplog_binary.exists():
            warnings.append(f"CmpLog config requested, but {cmplog_binary} does not exist yet")

    env = dict(settings.env)
    if row.grammar:
        if settings.custom_mutator_library:
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = settings.custom_mutator_library
        else:
            warnings.append("grammar config requested, but afl.custom_mutator_library is not configured")
    if row.smt and smt_count == 0:
        warnings.append(f"SMT config requested, but no files were found in {root_path / settings.smt_corpus_dir}")

    argv = [
        settings.fuzzer,
        "-i",
        str(input_dir),
        "-o",
        str(output_dir),
        "-m",
        str(settings.memory_mb),
        "-t",
        str(settings.timeout_ms),
    ]
    if dictionary_path is not None:
        argv.extend(["-x", str(dictionary_path)])
    if cmplog_binary is not None:
        argv.extend(["-c", str(cmplog_binary)])
    argv.extend(["--", str(binary_path), "@@"])

    return AFLPlan(
        target_id=target.id,
        config_id=row.id,
        config_name=row.name,
        argv=argv,
        env=env,
        input_dir=str(input_dir),
        output_dir=str(output_dir),
        dictionary=str(dictionary_path) if dictionary_path is not None else None,
        cmplog_binary=str(cmplog_binary) if cmplog_binary is not None else None,
        warnings=warnings,
    )


def prepare_dictionary(root: Path, settings: AFLSettings, target: TargetConfig) -> Path:
    output_dir = root / settings.work_dir / "dicts"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{target.id}.dict"
    seen: set[str] = set()
    lines: list[str] = []
    for relative_path in target.dictionaries:
        dictionary_path = root / relative_path
        if not dictionary_path.exists():
            raise FileNotFoundError(f"dictionary not found: {dictionary_path}")
        for raw_line in dictionary_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line in seen:
                continue
            seen.add(line)
            lines.append(line)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def prepare_input_corpus(
    root: Path,
    settings: AFLSettings,
    target_id: str,
    row: ExperimentRow,
) -> tuple[Path, int]:
    input_dir = root / settings.work_dir / "input" / target_id / row.id
    input_dir.mkdir(parents=True, exist_ok=True)

    seed_dir = root / settings.input_seed_dir
    if not seed_dir.exists():
        raise FileNotFoundError(f"seed directory not found: {seed_dir}")
    _copy_inputs(seed_dir, input_dir, prefix="seed")

    smt_count = 0
    if row.smt:
        smt_dir = root / settings.smt_corpus_dir
        if smt_dir.exists():
            smt_count = _copy_inputs(smt_dir, input_dir, prefix="smt")
    return input_dir, smt_count


def run_afl_plan(plan: AFLPlan, *, execute: bool) -> int:
    if not execute:
        print_afl_plan(plan, as_json=False)
        return 0
    if shutil.which(plan.argv[0]) is None:
        print(f"AFL++ fuzzer not found in PATH: {plan.argv[0]}")
        return 2
    binary = Path(plan.argv[-2])
    if not binary.exists():
        print(f"target binary does not exist: {binary}")
        return 2
    env = os.environ.copy()
    env.update(plan.env)
    return subprocess.run(plan.argv, env=env, check=False).returncode


def print_afl_plan(plan: AFLPlan, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        return
    for warning in plan.warnings:
        print(f"WARNING: {warning}")
    if plan.env:
        env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(plan.env.items()))
        print(f"{env_prefix} {shlex.join(plan.argv)}")
    else:
        print(shlex.join(plan.argv))


def afl_build_env(configs_dir: str | Path) -> dict[str, str]:
    settings = load_afl_settings(configs_dir)
    return {
        "CC": settings.compiler_cc,
        "CXX": settings.compiler_cxx,
        "CFLAGS": "-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer",
        "CXXFLAGS": "-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer",
        "LDFLAGS": "-fsanitize=address,undefined",
    }


def _copy_inputs(source_dir: Path, destination_dir: Path, *, prefix: str) -> int:
    count = 0
    for source in sorted(source_dir.iterdir()):
        if not source.is_file() or source.name.startswith("."):
            continue
        destination = destination_dir / f"{prefix}-{source.name}"
        shutil.copy2(source, destination)
        count += 1
    return count
