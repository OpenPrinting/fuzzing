from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from parser_fuzzers.crash_dedup import dedup_run
from parser_fuzzers.multitarget_runner import load_profiles, run_multitarget_monitor
from parser_fuzzers.run_metrics import summarize_run_metrics, write_run_metrics


@dataclass(frozen=True)
class OssFuzzStatus:
    oss_fuzz_dir: str
    project_dir: str
    project_yaml: str
    dockerfile: str
    run_tests: str
    docker_available: bool
    project_exists: bool
    has_project_build_sh: bool
    build_sh_source: str
    official_available_locally: bool
    reason: str
    helper_commands: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LocalComparisonResult:
    comparison_id: str
    work_root: str
    baseline_run_dir: str
    optimized_run_dir: str
    baseline_metrics: str
    optimized_metrics: str
    comparison_json: str
    comparison_md: str
    baseline_coverage_json: str
    optimized_coverage_json: str
    oss_fuzz_status: OssFuzzStatus

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["oss_fuzz_status"] = self.oss_fuzz_status.to_dict()
        return payload


def inspect_oss_fuzz_cups_filters(oss_fuzz_dir: str | Path) -> OssFuzzStatus:
    root = Path(oss_fuzz_dir)
    project_dir = root / "projects" / "cups-filters"
    project_yaml = project_dir / "project.yaml"
    dockerfile = project_dir / "Dockerfile"
    run_tests = project_dir / "run_tests.sh"
    has_project_build_sh = (project_dir / "build.sh").exists()
    build_sh_source = _extract_build_sh_source(dockerfile)
    docker_available = shutil.which("docker") is not None
    project_exists = project_yaml.exists() and dockerfile.exists()
    official_available = project_exists and docker_available
    if not project_exists:
        reason = "missing OSS-Fuzz cups-filters project metadata"
    elif not docker_available:
        reason = "docker is not available; official OSS-Fuzz helper commands cannot run locally"
    elif not has_project_build_sh and build_sh_source:
        reason = "official build script is supplied through the Dockerfile from OpenPrinting/fuzzing"
    else:
        reason = "official OSS-Fuzz helper commands should be usable"
    return OssFuzzStatus(
        oss_fuzz_dir=str(root),
        project_dir=str(project_dir),
        project_yaml=str(project_yaml) if project_yaml.exists() else "",
        dockerfile=str(dockerfile) if dockerfile.exists() else "",
        run_tests=str(run_tests) if run_tests.exists() else "",
        docker_available=docker_available,
        project_exists=project_exists,
        has_project_build_sh=has_project_build_sh,
        build_sh_source=build_sh_source,
        official_available_locally=official_available,
        reason=reason,
        helper_commands=[
            "python3 infra/helper.py build_image cups-filters",
            "python3 infra/helper.py build_fuzzers --sanitizer address --engine libfuzzer cups-filters",
            "python3 infra/helper.py run_fuzzer cups-filters <fuzzer-name>",
            "python3 infra/helper.py coverage cups-filters",
        ],
    )


def run_local_baseline_comparison(
    *,
    config_path: str | Path,
    work_root: str | Path,
    oss_fuzz_dir: str | Path,
    duration_sec: int,
    workers: int,
    timeout_sec: int,
    max_run_gb: float = 0.0,
    enable_llvm_profiles: bool = False,
    export_llvm_coverage: bool = False,
    optimized_policy: str = "avoidance",
) -> LocalComparisonResult:
    comparison_id = time.strftime("%Y%m%d-%H%M%S")
    root = Path(work_root) / comparison_id
    root.mkdir(parents=True, exist_ok=True)
    config = Path(config_path)
    oss_status = inspect_oss_fuzz_cups_filters(oss_fuzz_dir)
    objects = _coverage_objects_from_config(config)

    baseline_env = {
        "SMT_FUZZER_ENABLE_LLVM_PROFILES": "1" if enable_llvm_profiles else "",
        "SMT_FUZZER_HAZARD_SKIP_AFTER": "0",
        "SMT_FUZZER_SEMANTIC_SKIP_AFTER": "0",
        "SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL": "0",
        "SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE": "0",
        "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "0",
        "SMT_FUZZER_DISABLE_SCHEDULER_CRASH_PENALTY": "0",
    }
    normalized_policy = _normalize_optimized_policy(optimized_policy)
    optimized_env = _optimized_policy_env(normalized_policy, enable_llvm_profiles)

    baseline_root = root / "baseline"
    optimized_root = root / "optimized"
    with _patched_environ(baseline_env):
        baseline_summary = run_multitarget_monitor(
            config_path=config,
            work_root=baseline_root,
            workers=workers,
            cases_per_target=None,
            duration_sec=duration_sec,
            timeout_sec=timeout_sec,
            max_run_gb=max_run_gb or None,
            run_command=_run_command(
                config,
                baseline_root,
                duration_sec,
                workers,
                timeout_sec,
                max_run_gb,
                variant="baseline",
            ),
            capture_stdout=False,
            discovery_mode="coverage",
            scheduler="round-robin",
            runtime_skip=False,
            crash_skip_after=999999,
            prune_uninteresting=False,
            summary_mode="concise",
        )

    with _patched_environ(optimized_env):
        optimized_summary = run_multitarget_monitor(
            config_path=config,
            work_root=optimized_root,
            workers=workers,
            cases_per_target=None,
            duration_sec=duration_sec,
            timeout_sec=timeout_sec,
            max_run_gb=max_run_gb or None,
            run_command=_run_command(
                config,
                optimized_root,
                duration_sec,
                workers,
                timeout_sec,
                max_run_gb,
                variant="optimized",
                optimized_policy=normalized_policy,
            ),
            capture_stdout=False,
            discovery_mode="coverage",
            scheduler="novelty",
            runtime_skip=normalized_policy == "avoidance",
            crash_skip_after=1 if normalized_policy == "avoidance" else 999999,
            generalized_skip=normalized_policy == "avoidance",
            family_skip_after=32,
            skip_probe_rate=0.01 if normalized_policy == "avoidance" else 0.0,
            prune_uninteresting=False,
            summary_mode="concise",
        )

    baseline_run_dir = Path(baseline_summary.work_dir)
    optimized_run_dir = Path(optimized_summary.work_dir)
    dedup_run(baseline_run_dir, output_json=baseline_run_dir / "dedup.json", output_md=baseline_run_dir / "dedup.md")
    dedup_run(optimized_run_dir, output_json=optimized_run_dir / "dedup.json", output_md=optimized_run_dir / "dedup.md")

    baseline_coverage_json = ""
    optimized_coverage_json = ""
    if export_llvm_coverage:
        baseline_coverage_json = _export_llvm_coverage(baseline_run_dir, objects, root / "coverage" / "baseline")
        optimized_coverage_json = _export_llvm_coverage(optimized_run_dir, objects, root / "coverage" / "optimized")

    metrics_dir = root / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    baseline_metrics_path = metrics_dir / "baseline.json"
    optimized_metrics_path = metrics_dir / "optimized.json"
    baseline_metrics = summarize_run_metrics(
        baseline_run_dir,
        llvm_coverage_json=baseline_coverage_json or None,
    )
    optimized_metrics = summarize_run_metrics(
        optimized_run_dir,
        llvm_coverage_json=optimized_coverage_json or None,
    )
    write_run_metrics(baseline_metrics, baseline_metrics_path)
    write_run_metrics(optimized_metrics, optimized_metrics_path)

    comparison = build_comparison_payload(
        comparison_id=comparison_id,
        config_path=config,
        baseline=baseline_metrics,
        optimized=optimized_metrics,
        oss_fuzz_status=oss_status,
        optimized_policy=normalized_policy,
    )
    comparison_json = root / "comparison.json"
    comparison_md = root / "comparison.md"
    comparison_json.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    comparison_md.write_text(render_comparison_markdown(comparison), encoding="utf-8")

    return LocalComparisonResult(
        comparison_id=comparison_id,
        work_root=str(root),
        baseline_run_dir=str(baseline_run_dir),
        optimized_run_dir=str(optimized_run_dir),
        baseline_metrics=str(baseline_metrics_path),
        optimized_metrics=str(optimized_metrics_path),
        comparison_json=str(comparison_json),
        comparison_md=str(comparison_md),
        baseline_coverage_json=baseline_coverage_json,
        optimized_coverage_json=optimized_coverage_json,
        oss_fuzz_status=oss_status,
    )


def build_comparison_payload(
    *,
    comparison_id: str,
    config_path: str | Path,
    baseline: dict[str, Any],
    optimized: dict[str, Any],
    oss_fuzz_status: OssFuzzStatus,
    optimized_policy: str = "avoidance",
) -> dict[str, Any]:
    normalized_policy = _normalize_optimized_policy(optimized_policy)
    if normalized_policy == "avoidance":
        optimized_label = "smt-semantic-feedback-with-crash-avoidance"
        policy_note = (
            "The optimized run enables novelty scheduling, runtime crash-shape suppression, "
            "semantic suppression, and deterministic skip probes."
        )
    else:
        optimized_label = "smt-semantic-feedback-without-crash-avoidance"
        policy_note = (
            "The optimized run keeps novelty scheduling but disables runtime crash-shape "
            "suppression, semantic suppression, generalized skip, deterministic skip probes, "
            "and scheduler crash/repeat-crash penalties."
        )
    return {
        "comparison_id": comparison_id,
        "config_path": str(config_path),
        "baseline_label": "local-oss-fuzz-style-baseline",
        "optimized_label": optimized_label,
        "optimized_policy": normalized_policy,
        "oss_fuzz_status": oss_fuzz_status.to_dict(),
        "metrics": {
            "baseline": _selected_metrics(baseline),
            "optimized": _selected_metrics(optimized),
            "delta": _metric_delta(_selected_metrics(baseline), _selected_metrics(optimized)),
        },
        "interpretation": [
            "No private reproducer is added to either run.",
            "Both local variants use the same target config and generated input families.",
            policy_note,
            "When Docker is unavailable this is not an official OSS-Fuzz execution; it is a local, fair baseline using the same metrics contract.",
        ],
    }


def render_comparison_markdown(payload: dict[str, Any]) -> str:
    baseline = payload["metrics"]["baseline"]
    optimized = payload["metrics"]["optimized"]
    delta = payload["metrics"]["delta"]
    oss = payload["oss_fuzz_status"]
    rows = [
        ("cases", "cases"),
        ("retained_cases", "retained"),
        ("coverage_features", "features"),
        ("features_per_min", "features/min"),
        ("retained_density", "retained density"),
        ("crashes", "crashes"),
        ("unique_crashes", "unique crashes"),
        ("repeat_crash_records", "repeat crash records"),
        ("crash_density", "crash density"),
        ("skipped", "skipped"),
        ("llvm_functions_percent", "LLVM funcs %"),
        ("llvm_lines_percent", "LLVM lines %"),
        ("llvm_branches_percent", "LLVM branches %"),
    ]
    lines = [
        f"# Baseline Comparison {payload['comparison_id']}",
        "",
        "## OSS-Fuzz Availability",
        "",
        f"- Project exists: `{oss['project_exists']}`",
        f"- Docker available: `{oss['docker_available']}`",
        f"- Official helper usable locally: `{oss['official_available_locally']}`",
        f"- Reason: `{oss['reason']}`",
        "",
        "Official commands when Docker is available:",
        "",
    ]
    lines.extend(f"- `{command}`" for command in oss["helper_commands"])
    lines.extend(
        [
            "",
            "## Local Fair Comparison",
            "",
            "| Metric | Baseline | Optimized | Delta |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for key, label in rows:
        lines.append(
            f"| {label} | {_fmt_metric(baseline.get(key))} | "
            f"{_fmt_metric(optimized.get(key))} | {_fmt_metric(delta.get(key))} |"
        )
    lines.extend(
        [
            "",
            "## Notes",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in payload["interpretation"])
    lines.append("")
    return "\n".join(lines)


def _selected_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    run = payload.get("run", {})
    derived = payload.get("derived", {})
    totals = payload.get("llvm_cov", {}).get("totals", {})
    return {
        "run_dir": payload.get("run_dir", ""),
        "elapsed_sec": run.get("elapsed_sec", 0),
        "cases": run.get("cases", 0),
        "retained_cases": run.get("retained_cases", 0),
        "coverage_features": run.get("coverage_features", 0),
        "crashes": run.get("crashes", 0),
        "unique_crashes": run.get("unique_crashes", 0),
        "timeouts": run.get("timeouts", 0),
        "skipped": run.get("skipped", 0),
        "features_per_min": derived.get("features_per_min", 0),
        "retained_density": derived.get("retained_density", 0),
        "crash_density": derived.get("crash_density", 0),
        "repeat_crash_records": max(0, int(run.get("crashes", 0)) - int(run.get("unique_crashes", 0))),
        "llvm_functions_count": _coverage_count(totals, "functions"),
        "llvm_functions_percent": _coverage_percent(totals, "functions"),
        "llvm_lines_count": _coverage_count(totals, "lines"),
        "llvm_lines_percent": _coverage_percent(totals, "lines"),
        "llvm_branches_count": _coverage_count(totals, "branches"),
        "llvm_branches_percent": _coverage_percent(totals, "branches"),
    }


def _metric_delta(baseline: dict[str, Any], optimized: dict[str, Any]) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for key, base_value in baseline.items():
        opt_value = optimized.get(key)
        if isinstance(base_value, (int, float)) and isinstance(opt_value, (int, float)):
            delta[key] = round(float(opt_value) - float(base_value), 6)
    return delta


def _coverage_count(totals: dict[str, Any], key: str) -> int:
    value = totals.get(key, {})
    if not isinstance(value, dict):
        return 0
    return int(value.get("covered", 0) or value.get("count", 0) or 0)


def _coverage_percent(totals: dict[str, Any], key: str) -> float:
    value = totals.get(key, {})
    if not isinstance(value, dict):
        return 0.0
    return round(float(value.get("percent", 0.0) or 0.0), 3)


def _fmt_metric(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    if value is None:
        return ""
    return str(value)


def _coverage_objects_from_config(config_path: Path) -> list[str]:
    objects: list[str] = []
    for profile in load_profiles(config_path):
        path = Path(profile.filter_binary)
        if not path.is_absolute():
            path = Path.cwd() / path
        if path.exists():
            resolved = str(path)
            if resolved not in objects:
                objects.append(resolved)
    return objects


def _export_llvm_coverage(run_dir: Path, objects: list[str], out_dir: Path) -> str:
    profiles = sorted(str(path) for path in run_dir.rglob("*.profraw") if path.is_file() and path.stat().st_size > 0)
    if not profiles or not objects:
        return ""
    profdata = _which_llvm_tool("llvm-profdata")
    cov = _which_llvm_tool("llvm-cov")
    if not profdata or not cov:
        return ""
    out_dir.mkdir(parents=True, exist_ok=True)
    profdata_path = out_dir / "coverage.profdata"
    subprocess.run([profdata, "merge", "-sparse", *profiles, "-o", str(profdata_path)], check=True)
    first, *rest = objects
    object_args = [f"-object={path}" for path in rest]
    coverage_json = out_dir / "coverage.json"
    coverage_txt = out_dir / "coverage.txt"
    exported = subprocess.run(
        [cov, "export", first, f"-instr-profile={profdata_path}", *object_args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    coverage_json.write_text(exported.stdout, encoding="utf-8")
    reported = subprocess.run(
        [cov, "report", first, f"-instr-profile={profdata_path}", *object_args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    coverage_txt.write_text(reported.stdout, encoding="utf-8")
    return str(coverage_json)


def _which_llvm_tool(base: str) -> str:
    for candidate in (f"{base}-18", f"{base}-17", f"{base}-16", base):
        path = shutil.which(candidate)
        if path:
            return path
    return ""


def _extract_build_sh_source(dockerfile: Path) -> str:
    if not dockerfile.exists():
        return ""
    for line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if "oss_fuzz_build.sh" in stripped and "build.sh" in stripped:
            return stripped
    return ""


def _run_command(
    config: Path,
    work_root: Path,
    duration_sec: int,
    workers: int,
    timeout_sec: int,
    max_run_gb: float,
    *,
    variant: str,
    optimized_policy: str = "avoidance",
) -> str:
    args = [
        "PYTHONPATH=src",
        "python3",
        "-m",
        "parser_fuzzers.cli",
        "multitarget-monitor",
        "--config",
        str(config),
        "--work-root",
        str(work_root),
        "--duration-sec",
        str(duration_sec),
        "--workers",
        str(workers),
        "--timeout-sec",
        str(timeout_sec),
    ]
    if max_run_gb:
        args.extend(["--max-run-gb", f"{max_run_gb:g}"])
    args.extend(["--discovery-mode", "coverage"])
    if variant == "optimized":
        args.extend(
            [
                "--scheduler",
                "novelty",
            ]
        )
        if optimized_policy == "avoidance":
            args.extend(
                [
                    "--runtime-skip",
                    "--crash-skip-after",
                    "1",
                    "--generalized-skip",
                    "--skip-probe-rate",
                    "0.01",
                ]
            )
    else:
        args.extend(["--scheduler", "round-robin"])
    return " ".join(args)


def _normalize_optimized_policy(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"avoidance", "with-avoidance", "crash-avoidance"}:
        return "avoidance"
    if normalized in {"no-crash-avoidance", "without-avoidance", "no-avoidance", "novelty-only"}:
        return "no-crash-avoidance"
    raise ValueError(f"unknown optimized policy: {value}")


def _optimized_policy_env(policy: str, enable_llvm_profiles: bool) -> dict[str, str]:
    env = {
        "SMT_FUZZER_ENABLE_LLVM_PROFILES": "1" if enable_llvm_profiles else "",
    }
    if policy == "avoidance":
        env.update(
            {
                "SMT_FUZZER_HAZARD_SKIP_AFTER": "1",
                "SMT_FUZZER_SEMANTIC_SKIP_AFTER": "1",
                "SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL": "32",
                "SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE": "0.06",
                "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "1",
                "SMT_FUZZER_DISABLE_SCHEDULER_CRASH_PENALTY": "0",
            }
        )
    else:
        env.update(
            {
                "SMT_FUZZER_HAZARD_SKIP_AFTER": "0",
                "SMT_FUZZER_SEMANTIC_SKIP_AFTER": "0",
                "SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL": "0",
                "SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE": "0",
                "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "0",
                "SMT_FUZZER_DISABLE_SCHEDULER_CRASH_PENALTY": "1",
            }
        )
    return env


@contextlib.contextmanager
def _patched_environ(updates: dict[str, str]) -> Iterator[None]:
    old_values: dict[str, str | None] = {}
    for key, value in updates.items():
        old_values[key] = os.environ.get(key)
        if value == "":
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in old_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
