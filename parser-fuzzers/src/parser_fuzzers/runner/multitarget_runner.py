from __future__ import annotations

import concurrent.futures
import hashlib
import json
import math
import os
import re
import shutil
import shlex
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from parser_fuzzers.crash_dedup import compute_crash_signature
from parser_fuzzers.semantic_shapes import (
    build_planned_shape,
    build_result_shape_bundle,
    compact_shape_record,
    semantic_runtime_key,
    shape_feature_tokens,
)
from parser_fuzzers.image_templates import IMAGE_FEEDBACK_PERIOD, image_feedback_instance
from parser_fuzzers.document_harness import (
    COMMAND_COVERAGE_CASES,
    COMMAND_SEMANTIC_CASES,
    OFF_CUPS_BITS_PER_PIXEL,
    OFF_CUPS_BYTES_PER_LINE,
    OFF_CUPS_COLOR_ORDER,
    OFF_CUPS_COLOR_SPACE,
    OFF_CUPS_COMPRESSION,
    OFF_CUPS_HEIGHT,
    OFF_CUPS_ROW_COUNT,
    OFF_CUPS_WIDTH,
    OFF_HW_RESOLUTION,
    PDF_COVERAGE_CASES,
    PDF_SEMANTIC_PERIOD,
    POSTSCRIPT_COVERAGE_CASES,
    POSTSCRIPT_SEMANTIC_CASES,
    PWG_BOUNDARY_CASES,
    PWG_COVERAGE_CASES,
    PWG_GENERAL_CASES,
    RASTER_BOUNDARY_CASES,
    RASTER_COVERAGE_CASES,
    RASTER_GENERAL_CASES,
    TEXT_COVERAGE_CASES,
    TEXT_SEMANTIC_CASES,
    IMAGE_COVERAGE_CASES,
    make_document,
)
from parser_fuzzers.ppd_templates import (
    COVERAGE_RESOLUTIONS,
    FILTER_COVERAGE_PPDS,
    GENERAL_RESOLUTIONS,
    GENERAL_STRING_VALUES,
    GENERIC_RESOLUTIONS,
    GENERIC_STRING_VALUES,
    PAGE_SIZES,
    make_ppd,
)
from parser_fuzzers.structured_templates import (
    CUPS_FEEDBACK_PERIOD,
    CUPS_STRUCTURAL_PERIOD,
    PWG_FEEDBACK_PERIOD,
    PWG_STRUCTURAL_PERIOD,
)
from parser_fuzzers.template_synth import (
    CUPS_RASTER_SYNTH_PERIOD,
    IMAGE_SYNTH_PERIOD,
    PPD_SYNTH_PERIOD,
    PWG_RASTER_SYNTH_PERIOD,
)


RASTERTOESCPX_DOTROWSTEP_ZERO_MODS = {3, 4, 6, 8, 9, 11}
COVERAGE_OPTION_PERIOD = math.lcm(4, 8, 12, 15, len(PAGE_SIZES))
DOCUMENT_PERIODS = {
    "text": 1,
    "text_coverage_sweep": len(TEXT_COVERAGE_CASES),
    "text_semantic_sweep": len(TEXT_SEMANTIC_CASES),
    "postscript": 1,
    "postscript_coverage_sweep": len(POSTSCRIPT_COVERAGE_CASES),
    "postscript_semantic_sweep": len(POSTSCRIPT_SEMANTIC_CASES),
    "pdf_coverage_sweep": len(PDF_COVERAGE_CASES),
    "pdf_semantic_sweep": PDF_SEMANTIC_PERIOD,
    "image_coverage_sweep": IMAGE_SYNTH_PERIOD,
    "image_feedback_sweep": IMAGE_FEEDBACK_PERIOD,
    "command_coverage_sweep": len(COMMAND_COVERAGE_CASES),
    "command_semantic_sweep": len(COMMAND_SEMANTIC_CASES),
    "cups_raster_basic": 1,
    "cups_raster_mode10": COVERAGE_OPTION_PERIOD,
    "cups_raster_boundary_sweep": len(RASTER_BOUNDARY_CASES),
    "cups_raster_general_sweep": len(RASTER_GENERAL_CASES),
    "cups_raster_coverage_sweep": CUPS_RASTER_SYNTH_PERIOD,
    "cups_raster_structural_sweep": CUPS_STRUCTURAL_PERIOD,
    "cups_raster_feedback_sweep": CUPS_FEEDBACK_PERIOD,
    "pwg_raster_resolution_stress": 2,
    "pwg_raster_boundary_sweep": len(PWG_BOUNDARY_CASES),
    "pwg_raster_general_sweep": len(PWG_GENERAL_CASES),
    "pwg_raster_coverage_sweep": PWG_RASTER_SYNTH_PERIOD,
    "pwg_raster_structural_sweep": PWG_STRUCTURAL_PERIOD,
    "pwg_raster_feedback_sweep": PWG_FEEDBACK_PERIOD,
}
PPD_PERIODS = {
    "rastertopclx": len(GENERAL_STRING_VALUES),
    "rastertopclx_string_sweep": len(GENERIC_STRING_VALUES),
    "rastertopclx_general_strings": len(GENERAL_STRING_VALUES),
    "rastertopclx_plain": 1,
    "rastertoescpx_single_pagesize": 1,
    "rastertoescpx_size_sweep": 1,
    "raster_coverage_options": PPD_SYNTH_PERIOD,
    "rastertops_plain": 1,
    "rastertopwg_plain": 1,
    "pwgtopdf_plain": 1,
    "pwgtopdf_coverage_options": PPD_SYNTH_PERIOD,
    "pwgtoraster_1dpi": 1,
    "pwg_resolution_sweep": len(GENERIC_RESOLUTIONS),
    "pwg_resolution_general": len(GENERAL_RESOLUTIONS),
    "pwg_resolution_coverage": PPD_SYNTH_PERIOD,
}
for _filter_ppd_kind in FILTER_COVERAGE_PPDS:
    PPD_PERIODS[_filter_ppd_kind] = PPD_SYNTH_PERIOD

JOB_OPTION_PERIOD = PPD_SYNTH_PERIOD
JOB_COLOR_MODELS = ["Gray", "RGB", "CMYK", "Black"]
JOB_PRINT_QUALITIES = ["Draft", "Normal", "High", "Photo"]
JOB_MEDIA_TYPES = ["Plain", "Glossy", "Transparency", "Envelope"]
JOB_DUPLEX_MODES = ["None", "DuplexNoTumble", "DuplexTumble"]
JOB_SCALING_VALUES = ["100", "25", "50", "150", "200"]
JOB_NATURAL_SCALING_VALUES = ["100", "25", "50", "150", "200"]
JOB_ORIENTATIONS = ["3", "4", "5", "6"]
JOB_PRINT_SCALING = ["auto", "fit", "fill", "none"]


@dataclass
class TargetDiscoveryStats:
    submitted: int = 0
    completed: int = 0
    skipped: int = 0
    retained_cases: int = 0
    new_features: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    repeat_crashes: int = 0
    timeouts: int = 0
    runtime_suppressed: int = 0


@dataclass
class RunCounters:
    cases: int = 0
    crashes: int = 0
    reached: int = 0
    valid_ppds: int = 0
    timeouts: int = 0
    oracle_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class DiscoveryState:
    seen_features: set[str] = field(default_factory=set)
    seen_crash_signatures: set[str] = field(default_factory=set)
    crash_shape_counts: dict[str, int] = field(default_factory=dict)
    crash_hazard_counts: dict[str, int] = field(default_factory=dict)
    crash_family_counts: dict[str, int] = field(default_factory=dict)
    semantic_crash_counts: dict[str, int] = field(default_factory=dict)
    suppressed_case_shapes: dict[str, str] = field(default_factory=dict)
    suppressed_case_hazards: dict[str, str] = field(default_factory=dict)
    suppressed_case_families: dict[str, str] = field(default_factory=dict)
    suppressed_semantic_shapes: dict[str, str] = field(default_factory=dict)
    target_stats: dict[str, TargetDiscoveryStats] = field(default_factory=dict)
    scheduler_credit: dict[str, float] = field(default_factory=dict)
    scheduler_cursor: int = 0
    runtime_skip_enabled: bool = False
    crash_skip_after: int = 1
    hazard_skip_after: int = 0
    semantic_skip_after: int = 0
    generalized_skip_enabled: bool = False
    family_skip_after: int = 32
    retained_cases: int = 0
    unique_crashes: int = 0
    repeat_crashes: int = 0
    completed_cases: int = 0


@dataclass(frozen=True)
class TargetProfile:
    id: str
    description: str
    ppd_kind: str
    document_kind: str
    executor: str
    input_mime: str
    output_mime: str
    expected_filters: list[str]
    cases: int
    oracle: str
    filter_binary: str


@dataclass(frozen=True)
class CaseResult:
    target_id: str
    case_id: int
    target_description: str
    ppd_kind: str
    document_kind: str
    document_description: str
    work_dir: str
    ppd_path: str
    document_path: str
    command_path: str
    command_line: str
    job_options: str
    env_overrides: dict[str, str]
    compare_trace_path: str
    stdout_path: str
    stderr_path: str
    meta_path: str
    cupstestppd_ok: bool
    filters: list[str]
    reached_expected_filter: bool
    returncode: int | None
    timed_out: bool
    crashed: bool
    oracle: str
    duration_ms: float
    stderr_tail: list[str]


@dataclass(frozen=True)
class MultiTargetSummary:
    run_id: str
    work_dir: str
    config_path: str
    duration_budget_sec: int | None
    elapsed_sec: float
    workers: int
    timeout_sec: int
    max_run_bytes: int
    run_dir_bytes: int
    stop_reason: str
    targets: int
    cases: int
    crashes: int
    reached: int
    valid_ppds: int
    timeouts: int
    skipped: int
    pruned_cases: int
    skip_counts: dict[str, int]
    scheduler: str
    min_target_share: float
    max_target_share: float
    runtime_skip_enabled: bool
    auto_skip_state_enabled: bool
    auto_skip_search_root: str
    runtime_suppressed_shapes: int
    seeded_runtime_suppressed_shapes: int
    runtime_suppressed_hazards: int
    seeded_runtime_suppressed_hazards: int
    runtime_suppressed_families: int
    seeded_runtime_suppressed_families: int
    runtime_suppressed_semantic_shapes: int
    seeded_runtime_suppressed_semantic_shapes: int
    generalized_skip_enabled: bool
    family_skip_after: int
    hazard_skip_after: int
    semantic_skip_after: int
    skip_probe_rate: float
    skip_only_stop_after: int
    stagnation_stop_after_sec: int
    template_cycle_epochs: int
    llvm_profile_enabled: bool
    llvm_profile_files: int
    seed_skip_state_path: str
    target_stats: dict[str, dict[str, int]]
    retained_cases: int
    coverage_features: int
    unique_crashes: int
    repeat_crashes: int
    oracle_counts: dict[str, int]
    results: list[CaseResult]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def concise_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "work_dir": self.work_dir,
            "config_path": self.config_path,
            "duration_budget_sec": self.duration_budget_sec,
            "elapsed_sec": self.elapsed_sec,
            "workers": self.workers,
            "timeout_sec": self.timeout_sec,
            "max_run_bytes": self.max_run_bytes,
            "run_dir_bytes": self.run_dir_bytes,
            "stop_reason": self.stop_reason,
            "targets": self.targets,
            "cases": self.cases,
            "crashes": self.crashes,
            "reached": self.reached,
            "valid_ppds": self.valid_ppds,
            "timeouts": self.timeouts,
            "skipped": self.skipped,
            "pruned_cases": self.pruned_cases,
            "skip_counts": self.skip_counts,
            "scheduler": self.scheduler,
            "min_target_share": self.min_target_share,
            "max_target_share": self.max_target_share,
            "runtime_skip_enabled": self.runtime_skip_enabled,
            "auto_skip_state_enabled": self.auto_skip_state_enabled,
            "auto_skip_search_root": self.auto_skip_search_root,
            "runtime_suppressed_shapes": self.runtime_suppressed_shapes,
            "seeded_runtime_suppressed_shapes": self.seeded_runtime_suppressed_shapes,
            "runtime_suppressed_hazards": self.runtime_suppressed_hazards,
            "seeded_runtime_suppressed_hazards": self.seeded_runtime_suppressed_hazards,
            "runtime_suppressed_families": self.runtime_suppressed_families,
            "seeded_runtime_suppressed_families": self.seeded_runtime_suppressed_families,
            "runtime_suppressed_semantic_shapes": self.runtime_suppressed_semantic_shapes,
            "seeded_runtime_suppressed_semantic_shapes": self.seeded_runtime_suppressed_semantic_shapes,
            "generalized_skip_enabled": self.generalized_skip_enabled,
            "family_skip_after": self.family_skip_after,
            "hazard_skip_after": self.hazard_skip_after,
            "semantic_skip_after": self.semantic_skip_after,
            "skip_probe_rate": self.skip_probe_rate,
            "skip_only_stop_after": self.skip_only_stop_after,
            "stagnation_stop_after_sec": self.stagnation_stop_after_sec,
            "template_cycle_epochs": self.template_cycle_epochs,
            "llvm_profile_enabled": self.llvm_profile_enabled,
            "llvm_profile_files": self.llvm_profile_files,
            "seed_skip_state_path": self.seed_skip_state_path,
            "target_stats": self.target_stats,
            "retained_cases": self.retained_cases,
            "coverage_features": self.coverage_features,
            "unique_crashes": self.unique_crashes,
            "repeat_crashes": self.repeat_crashes,
            "oracle_counts": self.oracle_counts,
        }


def run_multitarget_monitor(
    *,
    config_path: str | Path,
    work_root: str | Path,
    workers: int,
    cases_per_target: int | None,
    duration_sec: int | None = None,
    timeout_sec: int = 15,
    max_run_gb: float | None = None,
    run_command: str = "",
    capture_stdout: bool = True,
    discovery_mode: str = "crash",
    scheduler: str = "round-robin",
    min_target_share: float = 0.0,
    max_target_share: float = 1.0,
    runtime_skip: bool = False,
    crash_skip_after: int = 1,
    prune_uninteresting: bool = False,
    seed_skip_state_path: str | Path | None = None,
    auto_skip_state: bool = False,
    auto_skip_search_root: str | Path | None = None,
    generalized_skip: bool = False,
    family_skip_after: int = 32,
    skip_probe_rate: float = 0.0,
    skip_only_stop_after: int = 0,
    stagnation_stop_after_sec: int = 0,
    summary_mode: str = "full",
    filter_root: str | Path | None = None,
) -> MultiTargetSummary:
    profiles = load_profiles(config_path, filter_root=filter_root)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    root = Path(work_root) / run_id
    root.mkdir(parents=True, exist_ok=True)
    resolved_seed_skip_state_path = Path(seed_skip_state_path) if seed_skip_state_path else None
    resolved_auto_skip_search_root = Path(auto_skip_search_root) if auto_skip_search_root else Path(work_root).parent
    if auto_skip_state and resolved_seed_skip_state_path is None:
        if _legacy_skip_state_enabled():
            resolved_seed_skip_state_path = find_latest_runtime_skip_state(resolved_auto_skip_search_root)
        else:
            resolved_seed_skip_state_path = find_latest_semantic_skip_state(
                resolved_auto_skip_search_root,
                [profile.id for profile in profiles],
            )
    started = time.monotonic()
    max_run_bytes = int(max_run_gb * 1024 * 1024 * 1024) if max_run_gb and max_run_gb > 0 else 0
    normalized_skip_probe_rate = max(0.0, min(1.0, skip_probe_rate))
    normalized_skip_only_stop_after = max(0, skip_only_stop_after)
    normalized_stagnation_stop_after_sec = max(0, stagnation_stop_after_sec)
    template_cycle_epochs = _template_cycle_epochs()
    llvm_profile_enabled = _llvm_profiles_enabled()
    hazard_skip_after = _hazard_skip_after()
    semantic_skip_after = _semantic_skip_after()
    normalized_min_target_share = _normalize_min_target_share(min_target_share, len(profiles))
    normalized_max_target_share = _normalize_max_target_share(
        max_target_share,
        len(profiles),
        normalized_min_target_share,
    )
    normalized_summary_mode = "concise" if summary_mode == "concise" else "full"
    stop_reason = "duration" if duration_sec is not None else "case-budget"
    last_size_check = 0.0
    last_run_dir_bytes = 0
    results: list[CaseResult] = []
    keep_results = normalized_summary_mode == "full"
    counters = RunCounters()
    skipped = 0
    pruned_cases = 0
    skip_counts: dict[str, int] = {}
    consecutive_skips_without_submission = 0
    last_novelty_time = started
    discovery_state = DiscoveryState(
        runtime_skip_enabled=runtime_skip,
        crash_skip_after=max(1, crash_skip_after),
        hazard_skip_after=hazard_skip_after,
        semantic_skip_after=semantic_skip_after,
        generalized_skip_enabled=generalized_skip,
        family_skip_after=max(1, family_skip_after),
    )
    _initialize_target_stats(discovery_state, profiles)
    seeded_runtime_suppressed_shapes = 0
    seeded_runtime_suppressed_hazards = 0
    seeded_runtime_suppressed_families = 0
    seeded_runtime_suppressed_semantic_shapes = 0
    if resolved_seed_skip_state_path:
        load_runtime_skip_state(
            discovery_state,
            resolved_seed_skip_state_path,
            generalized_skip=generalized_skip,
            family_skip_after=max(1, family_skip_after),
        )
        seeded_runtime_suppressed_shapes = len(discovery_state.suppressed_case_shapes)
        seeded_runtime_suppressed_hazards = len(discovery_state.suppressed_case_hazards)
        seeded_runtime_suppressed_families = len(discovery_state.suppressed_case_families)
        seeded_runtime_suppressed_semantic_shapes = len(discovery_state.suppressed_semantic_shapes)
    manifest = {
        "run_id": run_id,
        "work_dir": str(root),
        "config_path": str(config_path),
        "filter_root": str(filter_root) if filter_root else "",
        "workers": workers,
        "cases_per_target": cases_per_target,
        "duration_sec": duration_sec,
        "timeout_sec": timeout_sec,
        "max_run_gb": max_run_gb or 0,
        "max_run_bytes": max_run_bytes,
        "run_command": run_command,
        "capture_stdout": capture_stdout,
        "discovery_mode": discovery_mode,
        "scheduler": scheduler,
        "min_target_share": normalized_min_target_share,
        "max_target_share": normalized_max_target_share,
        "runtime_skip": runtime_skip,
        "crash_skip_after": max(1, crash_skip_after),
        "auto_skip_state": auto_skip_state,
        "auto_skip_search_root": str(resolved_auto_skip_search_root),
        "generalized_skip": generalized_skip,
        "family_skip_after": max(1, family_skip_after),
        "hazard_skip_after": hazard_skip_after,
        "semantic_skip_after": semantic_skip_after,
        "skip_probe_rate": normalized_skip_probe_rate,
        "skip_only_stop_after": normalized_skip_only_stop_after,
        "stagnation_stop_after_sec": normalized_stagnation_stop_after_sec,
        "template_cycle_epochs": template_cycle_epochs,
        "llvm_profile_enabled": llvm_profile_enabled,
        "summary_mode": normalized_summary_mode,
        "seed_skip_state_path": str(resolved_seed_skip_state_path) if resolved_seed_skip_state_path else "",
        "requested_seed_skip_state_path": str(seed_skip_state_path) if seed_skip_state_path else "",
        "seeded_runtime_suppressed_shapes": seeded_runtime_suppressed_shapes,
        "seeded_runtime_suppressed_hazards": seeded_runtime_suppressed_hazards,
        "seeded_runtime_suppressed_families": seeded_runtime_suppressed_families,
        "seeded_runtime_suppressed_semantic_shapes": seeded_runtime_suppressed_semantic_shapes,
        "prune_uninteresting": prune_uninteresting,
        "guidance_policy": (
            "general-format-aware; no private reproducer seeds; no issue-specific payload dictionary; "
            "valid PPD/raster templates with broad parser boundary values"
        ),
        "targets": [asdict(profile) for profile in profiles],
    }
    (root / "run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    timeline_path = root / "timeline.jsonl"
    commands_path = root / "commands.txt"
    (root / "run.log").write_text(
        "\n".join(
            [
                f"run_id={run_id}",
                f"config_path={config_path}",
                f"filter_root={filter_root or ''}",
                f"workers={workers}",
                f"cases_per_target={cases_per_target}",
                f"duration_sec={duration_sec}",
                f"timeout_sec={timeout_sec}",
                f"max_run_gb={max_run_gb or 0}",
                f"capture_stdout={capture_stdout}",
                f"discovery_mode={discovery_mode}",
                f"scheduler={scheduler}",
                f"min_target_share={normalized_min_target_share:g}",
                f"max_target_share={normalized_max_target_share:g}",
                f"runtime_skip={runtime_skip}",
                f"crash_skip_after={max(1, crash_skip_after)}",
                f"auto_skip_state={auto_skip_state}",
                f"auto_skip_search_root={resolved_auto_skip_search_root}",
                f"generalized_skip={generalized_skip}",
                f"family_skip_after={max(1, family_skip_after)}",
                f"hazard_skip_after={hazard_skip_after}",
                f"semantic_skip_after={semantic_skip_after}",
                f"skip_probe_rate={normalized_skip_probe_rate:g}",
                f"skip_only_stop_after={normalized_skip_only_stop_after}",
                f"stagnation_stop_after_sec={normalized_stagnation_stop_after_sec}",
                f"template_cycle_epochs={template_cycle_epochs}",
                f"llvm_profile_enabled={llvm_profile_enabled}",
                f"summary_mode={normalized_summary_mode}",
                f"seed_skip_state_path={resolved_seed_skip_state_path or ''}",
                f"prune_uninteresting={prune_uninteresting}",
                f"run_command={run_command}",
                "guidance=general-format-aware",
                "",
            ]
        ),
        encoding="utf-8",
    )
    if discovery_mode == "coverage" and duration_sec is None and not _skip_warm_template_cache():
        _warm_template_synth_cache(profiles)

    with timeline_path.open("a", encoding="utf-8") as timeline, commands_path.open("a", encoding="utf-8") as commands:
        if duration_sec is None:
            jobs: list[tuple[TargetProfile, int, Path]] = []
            for profile in profiles:
                count = cases_per_target if cases_per_target is not None else profile.cases
                for case_id in range(count):
                    if _run_dir_limit_reached(root, max_run_bytes):
                        stop_reason = "max-run-gb"
                        break
                    case_dir = root / profile.id / f"case-{case_id:04d}"
                    skip_reason = _combined_skip_reason(
                        profile,
                        case_id,
                        discovery_mode,
                        discovery_state,
                        skip_probe_rate=normalized_skip_probe_rate,
                    )
                    if skip_reason:
                        skipped += 1
                        skip_counts[skip_reason] = skip_counts.get(skip_reason, 0) + 1
                        _record_skip(discovery_state, profile, skip_reason)
                        _write_skip_record(profile, case_id, case_dir, skip_reason, timeline, commands)
                        consecutive_skips_without_submission += 1
                        if (
                            normalized_skip_only_stop_after
                            and consecutive_skips_without_submission >= normalized_skip_only_stop_after
                        ):
                            stop_reason = "skip-only"
                            break
                        continue
                    consecutive_skips_without_submission = 0
                    jobs.append((profile, case_id, case_dir))
                if stop_reason in {"max-run-gb", "skip-only"}:
                    break
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(run_case, profile, case_id, case_dir, timeout_sec, capture_stdout)
                    for profile, case_id, case_dir in jobs
                ]
                for profile, _, _ in jobs:
                    _record_submission(discovery_state, profile)
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if keep_results:
                        results.append(result)
                    _record_result_summary(counters, result)
                    extra = _process_discovery_result(result, root, discovery_mode, discovery_state)
                    _write_run_records(result, timeline, commands, extra)
                    if prune_uninteresting and _prune_case_artifacts(result, extra):
                        pruned_cases += 1
        else:
            deadline = started + duration_sec
            next_case_ids = {profile.id: 0 for profile in profiles}
            inflight_counts = {profile.id: 0 for profile in profiles}
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures: dict[concurrent.futures.Future[CaseResult], str] = {}
                while time.monotonic() < deadline or futures:
                    skip_streak = 0
                    while time.monotonic() < deadline and len(futures) < workers:
                        if stop_reason in {"max-run-gb", "skip-only", "coverage-stagnation"}:
                            break
                        now = time.monotonic()
                        if _coverage_stagnated(
                            discovery_mode,
                            normalized_stagnation_stop_after_sec,
                            discovery_state,
                            last_novelty_time,
                            now,
                        ):
                            stop_reason = "coverage-stagnation"
                            break
                        if max_run_bytes and now - last_size_check >= 5.0:
                            last_run_dir_bytes = _run_dir_size_bytes(root)
                            last_size_check = now
                            if last_run_dir_bytes >= max_run_bytes:
                                stop_reason = "max-run-gb"
                                break
                        profile = _choose_next_profile(
                            profiles,
                            discovery_state,
                            inflight_counts,
                            scheduler,
                            min_target_share=normalized_min_target_share,
                            max_target_share=normalized_max_target_share,
                        )
                        case_id = next_case_ids[profile.id]
                        next_case_ids[profile.id] += 1
                        case_dir = root / profile.id / f"case-{case_id:04d}"
                        skip_reason = _combined_skip_reason(
                            profile,
                            case_id,
                            discovery_mode,
                            discovery_state,
                            skip_probe_rate=normalized_skip_probe_rate,
                        )
                        if skip_reason:
                            skipped += 1
                            skip_counts[skip_reason] = skip_counts.get(skip_reason, 0) + 1
                            _record_skip(discovery_state, profile, skip_reason)
                            _write_skip_record(profile, case_id, case_dir, skip_reason, timeline, commands)
                            consecutive_skips_without_submission += 1
                            if (
                                normalized_skip_only_stop_after
                                and consecutive_skips_without_submission >= normalized_skip_only_stop_after
                            ):
                                stop_reason = "skip-only"
                                break
                            skip_streak += 1
                            if skip_streak >= max(100, workers * len(profiles) * 4):
                                break
                            continue
                        skip_streak = 0
                        consecutive_skips_without_submission = 0
                        _record_submission(discovery_state, profile)
                        inflight_counts[profile.id] += 1
                        future = executor.submit(run_case, profile, case_id, case_dir, timeout_sec, capture_stdout)
                        futures[future] = profile.id
                    if stop_reason in {"max-run-gb", "skip-only", "coverage-stagnation"} and not futures:
                        break
                    if not futures:
                        if time.monotonic() < deadline:
                            time.sleep(0.05)
                            continue
                        break
                    done, remaining = concurrent.futures.wait(
                        set(futures),
                        timeout=max(0.1, min(1.0, deadline - time.monotonic())),
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    remaining_map = {future: futures[future] for future in remaining}
                    for future in done:
                        target_id = futures.get(future, "")
                        if target_id:
                            inflight_counts[target_id] = max(0, inflight_counts[target_id] - 1)
                        result = future.result()
                        if keep_results:
                            results.append(result)
                        _record_result_summary(counters, result)
                        extra = _process_discovery_result(result, root, discovery_mode, discovery_state)
                        if _is_novel_discovery(extra):
                            last_novelty_time = time.monotonic()
                        _write_run_records(result, timeline, commands, extra)
                        if prune_uninteresting and _prune_case_artifacts(result, extra):
                            pruned_cases += 1
                    futures = remaining_map

    run_dir_bytes = _run_dir_size_bytes(root)
    llvm_profile_files = _count_llvm_profile_files(root)
    if keep_results:
        results.sort(key=lambda item: (item.target_id, item.case_id))
    summary = MultiTargetSummary(
        run_id=run_id,
        work_dir=str(root),
        config_path=str(config_path),
        duration_budget_sec=duration_sec,
        elapsed_sec=round(time.monotonic() - started, 3),
        workers=workers,
        timeout_sec=timeout_sec,
        max_run_bytes=max_run_bytes,
        run_dir_bytes=run_dir_bytes,
        stop_reason=stop_reason,
        targets=len(profiles),
        cases=counters.cases,
        crashes=counters.crashes,
        reached=counters.reached,
        valid_ppds=counters.valid_ppds,
        timeouts=counters.timeouts,
        skipped=skipped,
        pruned_cases=pruned_cases,
        skip_counts=dict(sorted(skip_counts.items())),
        scheduler=scheduler,
        min_target_share=normalized_min_target_share,
        max_target_share=normalized_max_target_share,
        runtime_skip_enabled=runtime_skip,
        auto_skip_state_enabled=auto_skip_state,
        auto_skip_search_root=str(resolved_auto_skip_search_root),
        runtime_suppressed_shapes=len(discovery_state.suppressed_case_shapes),
        seeded_runtime_suppressed_shapes=seeded_runtime_suppressed_shapes,
        runtime_suppressed_hazards=len(discovery_state.suppressed_case_hazards),
        seeded_runtime_suppressed_hazards=seeded_runtime_suppressed_hazards,
        runtime_suppressed_families=len(discovery_state.suppressed_case_families),
        seeded_runtime_suppressed_families=seeded_runtime_suppressed_families,
        runtime_suppressed_semantic_shapes=len(discovery_state.suppressed_semantic_shapes),
        seeded_runtime_suppressed_semantic_shapes=seeded_runtime_suppressed_semantic_shapes,
        generalized_skip_enabled=generalized_skip,
        family_skip_after=max(1, family_skip_after),
        hazard_skip_after=hazard_skip_after,
        semantic_skip_after=semantic_skip_after,
        skip_probe_rate=normalized_skip_probe_rate,
        skip_only_stop_after=normalized_skip_only_stop_after,
        stagnation_stop_after_sec=normalized_stagnation_stop_after_sec,
        template_cycle_epochs=template_cycle_epochs,
        llvm_profile_enabled=llvm_profile_enabled,
        llvm_profile_files=llvm_profile_files,
        seed_skip_state_path=str(resolved_seed_skip_state_path) if resolved_seed_skip_state_path else "",
        target_stats=_target_stats_summary(discovery_state),
        retained_cases=discovery_state.retained_cases,
        coverage_features=len(discovery_state.seen_features),
        unique_crashes=discovery_state.unique_crashes,
        repeat_crashes=discovery_state.repeat_crashes,
        oracle_counts=dict(sorted(counters.oracle_counts.items())),
        results=results,
    )
    concise_summary = summary.concise_dict()
    (root / "summary.concise.json").write_text(
        json.dumps(concise_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if normalized_summary_mode == "full":
        summary_payload = summary.to_dict()
    else:
        summary_payload = {
            **concise_summary,
            "summary_mode": "concise",
            "results_omitted": True,
            "results_source": "timeline.jsonl",
        }
    (root / "summary.json").write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_discovery_state(root, discovery_state)
    _write_standard_metrics(root)
    return summary


def run_case(
    profile: TargetProfile,
    case_id: int,
    case_dir: Path,
    timeout_sec: int = 15,
    capture_stdout: bool = True,
) -> CaseResult:
    case_dir.mkdir(parents=True, exist_ok=True)
    ppd_path = case_dir / "candidate.ppd"
    command_path = case_dir / "command.txt"
    stdout_path = case_dir / "stdout.bin"
    stderr_path = case_dir / "stderr.txt"
    meta_path = case_dir / "meta.json"

    ppd_path.write_text(make_ppd(profile.ppd_kind, case_id), encoding="utf-8")
    document = make_document(profile.document_kind, case_id, target_id=profile.id)
    document_path = case_dir / f"document{document.extension}"
    document_path.write_bytes(document.data)

    cupstestppd_ok = run_cupstestppd(ppd_path, case_dir / "cupstestppd.txt")
    filters = list_filters(profile, ppd_path, document_path, case_dir / "list_filters.stderr")
    reached = all(expected in filters for expected in profile.expected_filters)

    job_options = build_job_options(profile, case_id)
    command = build_command(profile, ppd_path, document_path, job_options=job_options)
    command_line = format_command(profile, ppd_path, command, case_dir)
    env_overrides = build_env_overrides(profile, ppd_path, case_dir)
    compare_trace_path = env_overrides.get("SMT_FUZZER_COMPARE_TRACE", "")
    command_path.write_text(command_line + "\n", encoding="utf-8")
    started = time.perf_counter()
    returncode: int | None = None
    timed_out = False
    stderr_text = ""
    try:
        if capture_stdout:
            stdout_handle = stdout_path.open("wb")
        else:
            stdout_path.write_text("stdout discarded for this campaign; replay command.txt to reproduce output.\n", encoding="utf-8")
            stdout_handle = Path(os.devnull).open("wb")
        with stdout_handle as stdout:
            completed = subprocess.run(
                command,
                stdout=stdout,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec,
                check=False,
                env=build_env(profile, ppd_path, case_dir),
            )
        returncode = completed.returncode
        stderr_text = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stderr_text = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    stderr_path.write_text(stderr_text, encoding="utf-8")
    crashed, oracle = classify(profile, stderr_text, returncode, timed_out)

    result = CaseResult(
        target_id=profile.id,
        case_id=case_id,
        target_description=profile.description,
        ppd_kind=profile.ppd_kind,
        document_kind=profile.document_kind,
        document_description=document.description,
        work_dir=str(case_dir),
        ppd_path=str(ppd_path),
        document_path=str(document_path),
        command_path=str(command_path),
        command_line=command_line,
        job_options=job_options,
        env_overrides=env_overrides,
        compare_trace_path=compare_trace_path,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        meta_path=str(meta_path),
        cupstestppd_ok=cupstestppd_ok,
        filters=filters,
        reached_expected_filter=reached,
        returncode=returncode,
        timed_out=timed_out,
        crashed=crashed,
        oracle=oracle,
        duration_ms=duration_ms,
        stderr_tail=_tail_lines(stderr_text, 12),
    )
    meta_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _write_standard_metrics(root: Path) -> None:
    try:
        from parser_fuzzers.run_metrics import write_standard_run_metrics

        write_standard_run_metrics(root)
    except Exception as exc:  # pragma: no cover - metrics must not break fuzz runs
        (root / "standard_metrics.error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")


def load_profiles(config_path: str | Path, *, filter_root: str | Path | None = None) -> list[TargetProfile]:
    data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    resolved_filter_root = Path(filter_root) if filter_root else None
    profiles = []
    for item in data.get("targets", []):
        executor = str(item["executor"])
        filter_binary = str(item.get("filter_binary", ""))
        if resolved_filter_root is not None and executor == "direct_filter":
            filter_binary = remap_filter_binary(filter_binary, resolved_filter_root)
        profiles.append(
            TargetProfile(
                id=str(item["id"]),
                description=str(item.get("description", "")),
                ppd_kind=str(item["ppd_kind"]),
                document_kind=str(item["document_kind"]),
                executor=executor,
                input_mime=str(item.get("input_mime", "")),
                output_mime=str(item.get("output_mime", "printer/foo")),
                expected_filters=[str(value) for value in item.get("expected_filters", [])],
                cases=int(item.get("cases", 1)),
                oracle=str(item.get("oracle", "crash_or_signal")),
                filter_binary=filter_binary,
            )
        )
    return profiles


def remap_filter_binary(filter_binary: str, filter_root: str | Path) -> str:
    name = Path(filter_binary).name if filter_binary else ""
    if not name:
        return filter_binary
    return str(Path(filter_root) / name)


def case_shape_key(profile: TargetProfile, case_id: int) -> str:
    ppd_period = PPD_PERIODS.get(profile.ppd_kind, 1)
    document_period = DOCUMENT_PERIODS.get(profile.document_kind, 1)
    document_slot = _shape_slot(case_id, document_period)
    document_epoch = _shape_epoch_suffix(profile, case_id, document_period)
    return "|".join(
        [
            f"target:{profile.id}",
            f"ppd:{profile.ppd_kind}:{_shape_slot(case_id, ppd_period)}",
            f"doc:{profile.document_kind}:{document_slot}{document_epoch}",
            f"options:{_shape_slot(case_id, JOB_OPTION_PERIOD) if build_job_options(profile, case_id) else 'off'}",
        ]
    )


def case_family_key(profile: TargetProfile) -> str:
    return "|".join(
        [
            f"target:{_target_family(profile.id)}",
            f"ppd:{profile.ppd_kind}",
            f"doc:{profile.document_kind}",
        ]
    )


def case_hazard_key(profile: TargetProfile, case_id: int) -> str:
    if profile.document_kind != "image_feedback_sweep":
        return ""
    image = image_feedback_instance(case_id, target_id=profile.id)
    if image.payload_delta < 0:
        payload = "short"
    elif image.payload_delta > 0:
        payload = "extra"
    else:
        payload = "exact"
    return "|".join(
        [
            f"target:{profile.id}",
            f"ppd:{profile.ppd_kind}",
            f"doc:{profile.document_kind}",
            f"fmt:{image.image_format}",
            f"objective:{image.objective}",
            f"payload:{payload}",
            f"interlace:{image.png_interlace}",
        ]
    )


def planned_semantic_runtime_key(profile: TargetProfile, case_id: int) -> str:
    semantic_hash = planned_semantic_input_hash(
        profile.id,
        profile.executor,
        profile.ppd_kind,
        profile.document_kind,
        profile.input_mime,
        profile.output_mime,
        tuple(profile.expected_filters),
        _semantic_case_slot(profile, case_id),
    )
    return semantic_runtime_key(profile.id, semantic_hash)


@lru_cache(maxsize=65536)
def planned_semantic_input_hash(
    target_id: str,
    executor: str,
    ppd_kind: str,
    document_kind: str,
    input_mime: str,
    output_mime: str,
    expected_filters: tuple[str, ...],
    semantic_case_id: int,
) -> str:
    document = make_document(document_kind, semantic_case_id, target_id=target_id)
    profile = TargetProfile(
        id=target_id,
        description="",
        ppd_kind=ppd_kind,
        document_kind=document_kind,
        executor=executor,
        input_mime=input_mime,
        output_mime=output_mime,
        expected_filters=list(expected_filters),
        cases=0,
        oracle="",
        filter_binary="",
    )
    job_options = build_job_options(profile, semantic_case_id)
    shape = build_planned_shape(
        target_id=target_id,
        ppd_kind=ppd_kind,
        document_kind=document_kind,
        input_mime=input_mime,
        output_mime=output_mime,
        expected_filters=list(expected_filters),
        ppd_text=make_ppd(ppd_kind, semantic_case_id),
        document_data=document.data,
        job_options=job_options,
    )
    return str(shape["semantic_input_hash"])


def _semantic_case_slot(profile: TargetProfile, case_id: int) -> int:
    ppd_period = max(1, PPD_PERIODS.get(profile.ppd_kind, 1))
    document_period = max(1, DOCUMENT_PERIODS.get(profile.document_kind, 1))
    if profile.document_kind == "image_feedback_sweep":
        document_period *= _template_cycle_epochs()
    option_period = JOB_OPTION_PERIOD if build_job_options(profile, case_id) else 1
    period = math.lcm(ppd_period, document_period, option_period)
    return case_id % max(1, period)


def runtime_skip_reason(profile: TargetProfile, case_id: int, state: DiscoveryState) -> str:
    if not state.runtime_skip_enabled:
        return ""
    semantic_reason = semantic_runtime_skip_reason(profile, case_id, state)
    if semantic_reason:
        return semantic_reason
    signature = state.suppressed_case_shapes.get(case_shape_key(profile, case_id))
    if signature:
        return f"runtime-known-crash-shape:{_short_signature_label(signature)}"
    hazard = case_hazard_key(profile, case_id)
    if hazard:
        signature = state.suppressed_case_hazards.get(hazard)
        if signature:
            return f"runtime-known-crash-hazard:{_short_signature_label(signature)}"
    if state.generalized_skip_enabled:
        family_signature = state.suppressed_case_families.get(case_family_key(profile))
        if family_signature:
            return f"runtime-known-crash-family:{_short_signature_label(family_signature)}"
    return ""


def semantic_runtime_skip_reason(profile: TargetProfile, case_id: int, state: DiscoveryState) -> str:
    if state.semantic_skip_after <= 0:
        return ""
    semantic_key = planned_semantic_runtime_key(profile, case_id)
    signature = state.suppressed_semantic_shapes.get(semantic_key)
    if signature:
        return f"runtime-known-crash-semantic-shape:{_short_signature_label(signature)}"
    return ""


def load_runtime_skip_state(
    state: DiscoveryState,
    state_path: str | Path,
    *,
    generalized_skip: bool = False,
    family_skip_after: int = 32,
) -> int:
    payload = json.loads(Path(state_path).read_text(encoding="utf-8"))
    loaded = 0
    if _legacy_skip_state_enabled():
        for item in payload.get("suppressed_case_shapes", []):
            if not isinstance(item, dict):
                continue
            shape = str(item.get("shape") or "")
            signature = str(item.get("signature") or "")
            if not shape or not signature:
                continue
            if shape not in state.suppressed_case_shapes:
                loaded += 1
            state.suppressed_case_shapes.setdefault(shape, signature)
            state.seen_crash_signatures.add(signature)
            if generalized_skip:
                _record_family_suppression_candidate(
                    state,
                    _shape_family_key(shape),
                    signature,
                    max(1, family_skip_after),
                )
        for item in payload.get("suppressed_case_hazards", []):
            if not isinstance(item, dict):
                continue
            hazard = str(item.get("hazard") or "")
            signature = str(item.get("signature") or "")
            if not hazard or not signature:
                continue
            state.suppressed_case_hazards.setdefault(hazard, signature)
            state.seen_crash_signatures.add(signature)
        if generalized_skip:
            for item in payload.get("suppressed_case_families", []):
                if not isinstance(item, dict):
                    continue
                family = str(item.get("family") or "")
                signature = str(item.get("signature") or "")
                if not family or not signature:
                    continue
                state.suppressed_case_families.setdefault(family, signature)
                state.seen_crash_signatures.add(signature)
    for item in payload.get("suppressed_semantic_shapes", []):
        if not isinstance(item, dict):
            continue
        semantic = str(item.get("semantic") or item.get("shape") or "")
        signature = str(item.get("signature") or "")
        if not semantic or not signature:
            continue
        if semantic not in state.suppressed_semantic_shapes:
            loaded += 1
        state.suppressed_semantic_shapes.setdefault(semantic, signature)
        state.seen_crash_signatures.add(signature)
    return loaded


def find_latest_runtime_skip_state(search_root: str | Path) -> Path | None:
    root = Path(search_root)
    if not root.exists():
        return None
    candidates: list[tuple[float, Path]] = []
    for state_path in _iter_runtime_skip_state_candidates(root):
        if _runtime_skip_state_has_suppression(state_path):
            try:
                candidates.append((state_path.stat().st_mtime, state_path))
            except OSError:
                continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], str(item[1])))[1]


def find_latest_semantic_skip_state(search_root: str | Path, target_ids: list[str]) -> Path | None:
    root = Path(search_root)
    if not root.exists():
        return None
    target_prefixes = tuple(f"target:{target_id}|" for target_id in target_ids)
    candidates: list[tuple[float, Path]] = []
    for state_path in _iter_runtime_skip_state_candidates(root):
        if not _semantic_skip_state_matches_targets(state_path, target_prefixes):
            continue
        try:
            candidates.append((state_path.stat().st_mtime, state_path))
        except OSError:
            continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], str(item[1])))[1]


def _semantic_skip_state_matches_targets(state_path: Path, target_prefixes: tuple[str, ...]) -> bool:
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    for item in payload.get("suppressed_semantic_shapes", []):
        if not isinstance(item, dict):
            continue
        semantic = str(item.get("semantic") or item.get("shape") or "")
        if not target_prefixes or semantic.startswith(target_prefixes):
            return True
    return False


def _iter_runtime_skip_state_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    direct = root / "discovery_state.json"
    if direct.exists():
        candidates.append(direct)
    try:
        first_level = [path for path in root.iterdir() if path.is_dir()]
    except OSError:
        return candidates
    for path in first_level:
        state = path / "discovery_state.json"
        if state.exists():
            candidates.append(state)
        try:
            second_level = [child for child in path.iterdir() if child.is_dir()]
        except OSError:
            continue
        for child in second_level:
            state = child / "discovery_state.json"
            if state.exists():
                candidates.append(state)
    return candidates


def _runtime_skip_state_has_suppression(state_path: Path) -> bool:
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not _legacy_skip_state_enabled():
        return bool(payload.get("suppressed_semantic_shapes"))
    return bool(
        payload.get("suppressed_case_shapes")
        or payload.get("suppressed_case_hazards")
        or payload.get("suppressed_case_families")
        or payload.get("suppressed_semantic_shapes")
    )


def record_runtime_crash_suppression(
    state: DiscoveryState,
    profile: TargetProfile,
    case_id: int,
    signature: str,
) -> bool:
    shape = case_shape_key(profile, case_id)
    count_key = f"{shape}|signature:{signature}"
    count = state.crash_shape_counts.get(count_key, 0) + 1
    state.crash_shape_counts[count_key] = count
    if count >= state.crash_skip_after:
        state.suppressed_case_shapes.setdefault(shape, signature)
        _record_hazard_suppression_candidate(state, profile, case_id, signature)
        if state.generalized_skip_enabled:
            _record_family_suppression_candidate(
                state,
                case_family_key(profile),
                signature,
                state.family_skip_after,
            )
        return True
    if state.generalized_skip_enabled:
        _record_family_suppression_candidate(
            state,
            case_family_key(profile),
            signature,
            state.family_skip_after,
        )
    _record_hazard_suppression_candidate(state, profile, case_id, signature)
    return False


def record_semantic_crash_suppression(
    state: DiscoveryState,
    result: CaseResult,
    shape_bundle: dict[str, Any],
    signature: str,
    *,
    retained: bool,
) -> bool:
    if state.semantic_skip_after <= 0 or retained:
        return False
    semantic_hash = str(shape_bundle.get("semantic_input_hash") or "")
    failure_hash = str(shape_bundle.get("failure_shape_hash") or "")
    if not semantic_hash or not failure_hash:
        return False
    semantic_key = semantic_runtime_key(result.target_id, semantic_hash)
    count_key = f"{semantic_key}|failure:{failure_hash}|signature:{signature}"
    count = state.semantic_crash_counts.get(count_key, 0) + 1
    state.semantic_crash_counts[count_key] = count
    if count >= state.semantic_skip_after:
        state.suppressed_semantic_shapes.setdefault(semantic_key, signature)
        return True
    return False


def _record_family_suppression_candidate(
    state: DiscoveryState,
    family: str,
    signature: str,
    threshold: int,
) -> bool:
    count_key = f"{family}|signature:{signature}"
    count = state.crash_family_counts.get(count_key, 0) + 1
    state.crash_family_counts[count_key] = count
    if count >= threshold:
        state.suppressed_case_families.setdefault(family, signature)
        return True
    return False


def _record_hazard_suppression_candidate(
    state: DiscoveryState,
    profile: TargetProfile,
    case_id: int,
    signature: str,
) -> bool:
    if state.hazard_skip_after <= 0:
        return False
    hazard = case_hazard_key(profile, case_id)
    if not hazard:
        return False
    count_key = f"{hazard}|signature:{signature}"
    count = state.crash_hazard_counts.get(count_key, 0) + 1
    state.crash_hazard_counts[count_key] = count
    if count >= state.hazard_skip_after:
        state.suppressed_case_hazards.setdefault(hazard, signature)
        return True
    return False


def _shape_family_key(shape: str) -> str:
    target = ""
    ppd = ""
    doc = ""
    for part in shape.split("|"):
        if part.startswith("target:"):
            target = _target_family(part.removeprefix("target:"))
        elif part.startswith("ppd:"):
            ppd = part.removeprefix("ppd:").split(":", 1)[0]
        elif part.startswith("doc:"):
            doc = part.removeprefix("doc:").split(":", 1)[0]
    return "|".join([f"target:{target}", f"ppd:{ppd}", f"doc:{doc}"])


def _target_family(target_id: str) -> str:
    for suffix in ("_coverage", "_general", "_explore", "_structural", "_feedback"):
        if target_id.endswith(suffix):
            return target_id.removesuffix(suffix)
    return target_id


def _shape_slot(case_id: int, period: int) -> str:
    if period <= 0:
        return str(case_id)
    return str(case_id % period)


def _shape_epoch_suffix(profile: TargetProfile, case_id: int, period: int) -> str:
    if profile.document_kind != "image_feedback_sweep" or period <= 0:
        return ""
    epochs = _template_cycle_epochs()
    if epochs <= 1:
        return ""
    return f":epoch{(case_id // period) % epochs}"


def _combined_skip_reason(
    profile: TargetProfile,
    case_id: int,
    discovery_mode: str,
    state: DiscoveryState,
    *,
    skip_probe_rate: float = 0.0,
) -> str:
    if discovery_mode != "coverage":
        return ""
    static_reason = coverage_skip_reason(profile, case_id)
    if static_reason:
        return static_reason
    runtime_reason = runtime_skip_reason(profile, case_id, state)
    if runtime_reason and _should_force_avoidance_probe(profile, case_id, state):
        return ""
    if runtime_reason and _should_probe_runtime_skip(profile, case_id, runtime_reason, skip_probe_rate):
        return ""
    return runtime_reason


def _should_force_avoidance_probe(profile: TargetProfile, case_id: int, state: DiscoveryState) -> bool:
    rate = _avoidance_skip_probe_rate()
    if rate <= 0.0:
        return False
    if _target_seeded_suppression_pressure(state, profile.id) <= 0.0:
        return False
    if _case_has_avoidable_image_hazard(profile, case_id, state):
        return True
    if rate >= 1.0:
        return True
    key = f"avoidance-probe|{profile.id}|{profile.ppd_kind}|{profile.document_kind}|{case_id}".encode("utf-8")
    value = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / float(1 << 64)
    return value < rate


def _case_has_avoidable_image_hazard(profile: TargetProfile, case_id: int, state: DiscoveryState) -> bool:
    hazard = case_hazard_key(profile, case_id)
    if not hazard:
        return False
    if hazard in state.suppressed_case_hazards:
        return True
    target_id = _key_field(hazard, "target")
    image_format = _key_field(hazard, "fmt")
    payload = _key_field(hazard, "payload")
    interlace = _key_field(hazard, "interlace")
    if not target_id or not image_format or not payload:
        return False
    for suppressed_hazard in state.suppressed_case_hazards:
        if not _same_or_derived_target(_key_field(suppressed_hazard, "target"), target_id):
            continue
        if _key_field(suppressed_hazard, "fmt") != image_format:
            continue
        if _key_field(suppressed_hazard, "payload") != payload:
            continue
        suppressed_interlace = _key_field(suppressed_hazard, "interlace")
        if suppressed_interlace and interlace and suppressed_interlace != interlace:
            continue
        return True
    return False


def _should_probe_runtime_skip(
    profile: TargetProfile,
    case_id: int,
    skip_reason: str,
    skip_probe_rate: float,
) -> bool:
    if skip_probe_rate <= 0.0:
        return False
    if skip_probe_rate >= 1.0:
        return True
    key = f"{profile.id}|{profile.ppd_kind}|{profile.document_kind}|{case_id}|{skip_reason}".encode("utf-8")
    value = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / float(1 << 64)
    return value < skip_probe_rate


def _initialize_target_stats(state: DiscoveryState, profiles: list[TargetProfile]) -> None:
    for profile in profiles:
        _target_stats(state, profile.id)
        state.scheduler_credit.setdefault(profile.id, 0.0)


def _target_stats(state: DiscoveryState, target_id: str) -> TargetDiscoveryStats:
    if target_id not in state.target_stats:
        state.target_stats[target_id] = TargetDiscoveryStats()
    return state.target_stats[target_id]


def _record_submission(state: DiscoveryState, profile: TargetProfile) -> None:
    _target_stats(state, profile.id).submitted += 1


def _record_skip(state: DiscoveryState, profile: TargetProfile, skip_reason: str) -> None:
    stats = _target_stats(state, profile.id)
    stats.skipped += 1
    if skip_reason.startswith("runtime-known-crash-"):
        stats.runtime_suppressed += 1


def _record_result_summary(counters: RunCounters, result: CaseResult) -> None:
    counters.cases += 1
    if result.crashed:
        counters.crashes += 1
    if result.reached_expected_filter:
        counters.reached += 1
    if result.cupstestppd_ok:
        counters.valid_ppds += 1
    if result.timed_out:
        counters.timeouts += 1
    oracle = result.oracle or "none"
    counters.oracle_counts[oracle] = counters.oracle_counts.get(oracle, 0) + 1


def _is_novel_discovery(extra: dict[str, Any] | None) -> bool:
    if not extra:
        return False
    return bool(extra.get("retained_for_coverage") or extra.get("new_crash_signature") is True)


def _coverage_stagnated(
    discovery_mode: str,
    stagnation_stop_after_sec: int,
    state: DiscoveryState,
    last_novelty_time: float,
    now: float,
) -> bool:
    if discovery_mode != "coverage" or stagnation_stop_after_sec <= 0:
        return False
    if state.completed_cases < 100:
        return False
    return now - last_novelty_time >= stagnation_stop_after_sec


def _choose_next_profile(
    profiles: list[TargetProfile],
    state: DiscoveryState,
    inflight_counts: dict[str, int],
    scheduler: str,
    *,
    min_target_share: float = 0.0,
    max_target_share: float = 1.0,
) -> TargetProfile:
    if not profiles:
        raise ValueError("no target profiles configured")
    normalized_min_share = _normalize_min_target_share(min_target_share, len(profiles))
    normalized_max_share = _normalize_max_target_share(max_target_share, len(profiles), normalized_min_share)
    floor_profile = _target_budget_floor_candidate(profiles, state, normalized_min_share)
    if floor_profile is not None:
        return floor_profile
    probe_profile = _avoidance_probe_candidate(profiles, state, inflight_counts, normalized_max_share)
    if probe_profile is not None:
        return probe_profile
    if scheduler == "round-robin":
        eligible_profiles = _target_budget_eligible_profiles(profiles, state, normalized_max_share)
        for _ in profiles:
            profile = profiles[state.scheduler_cursor % len(profiles)]
            state.scheduler_cursor += 1
            if profile in eligible_profiles:
                return profile
        return profiles[0]
    if scheduler != "novelty":
        raise ValueError(f"unknown scheduler: {scheduler}")

    eligible_profiles = _target_budget_eligible_profiles(profiles, state, normalized_max_share)
    scores = {profile.id: _target_scheduler_score(state, profile.id) for profile in profiles}
    total_score = sum(scores[profile.id] for profile in eligible_profiles) or 1.0
    for profile in profiles:
        state.scheduler_credit[profile.id] = state.scheduler_credit.get(profile.id, 0.0) + scores[profile.id]

    def rank(profile: TargetProfile) -> tuple[float, int, str]:
        stats = _target_stats(state, profile.id)
        adjusted_credit = state.scheduler_credit.get(profile.id, 0.0) / (1 + inflight_counts.get(profile.id, 0))
        return (adjusted_credit, -stats.submitted, profile.id)

    chosen = max(eligible_profiles, key=rank)
    state.scheduler_credit[chosen.id] = state.scheduler_credit.get(chosen.id, 0.0) - total_score
    return chosen


def _normalize_min_target_share(value: float, target_count: int) -> float:
    if target_count <= 0:
        return 0.0
    return max(0.0, min(float(value), 1.0 / target_count))


def _normalize_max_target_share(value: float, target_count: int, min_target_share: float = 0.0) -> float:
    if target_count <= 0:
        return 1.0
    if value <= 0.0:
        return 1.0
    lower_bound = max(min_target_share, 1.0 / target_count)
    return max(lower_bound, min(float(value), 1.0))


def _target_budget_attempts(state: DiscoveryState, target_id: str) -> int:
    stats = _target_stats(state, target_id)
    return stats.submitted + stats.skipped


def _target_budget_floor_candidate(
    profiles: list[TargetProfile],
    state: DiscoveryState,
    min_target_share: float,
) -> TargetProfile | None:
    if min_target_share <= 0.0:
        return None
    total_attempts = sum(_target_budget_attempts(state, profile.id) for profile in profiles)
    if total_attempts <= 0:
        return None

    def rank(profile: TargetProfile) -> tuple[float, int, float, str]:
        attempts = _target_budget_attempts(state, profile.id)
        share = attempts / total_attempts
        deficit = min_target_share - share
        return (deficit, -attempts, _target_scheduler_score(state, profile.id), profile.id)

    under_budget = [
        profile
        for profile in profiles
        if (_target_budget_attempts(state, profile.id) / total_attempts) < min_target_share
    ]
    if not under_budget:
        return None
    return max(under_budget, key=rank)


def _target_budget_eligible_profiles(
    profiles: list[TargetProfile],
    state: DiscoveryState,
    max_target_share: float,
) -> list[TargetProfile]:
    if max_target_share >= 1.0 or len(profiles) <= 1:
        return profiles
    total_attempts = sum(_target_budget_attempts(state, profile.id) for profile in profiles)
    if total_attempts <= 0:
        return profiles
    min_attempts = min(_target_budget_attempts(state, profile.id) for profile in profiles)
    eligible = []
    for profile in profiles:
        attempts = _target_budget_attempts(state, profile.id)
        projected_share = (attempts + 1) / (total_attempts + 1)
        if projected_share <= max_target_share or attempts == min_attempts:
            eligible.append(profile)
    return eligible or profiles


def _target_scheduler_score(state: DiscoveryState, target_id: str) -> float:
    stats = _target_stats(state, target_id)
    if stats.completed == 0:
        score = 3.0
    else:
        novelty_rate = stats.retained_cases / max(1, stats.completed)
        crash_rate = stats.crashes / max(1, stats.completed)
        repeat_crash_rate = stats.repeat_crashes / max(1, stats.crashes)
        score = 1.0 + (8.0 * novelty_rate) + min(4.0, 0.05 * stats.new_features)
        crash_penalty_disabled = _scheduler_crash_penalty_disabled()
        if stats.crashes and not crash_penalty_disabled:
            score *= 1.0 / (1.0 + 12.0 * crash_rate)
        if stats.repeat_crashes and not crash_penalty_disabled:
            score *= 1.0 / (1.0 + 4.0 * repeat_crash_rate)
        if (
            stats.completed >= 100
            and stats.crashes > max(20, stats.retained_cases * 10)
            and not crash_penalty_disabled
        ):
            score *= 0.25
    if stats.timeouts:
        score *= 1.0 / (1.0 + min(4.0, 0.1 * stats.timeouts))
    if stats.runtime_suppressed:
        score *= 1.0 / (1.0 + min(12.0, stats.runtime_suppressed / 20.0))
    suppression_pressure = _target_seeded_suppression_pressure(state, target_id)
    if suppression_pressure:
        score *= 1.0 / (1.0 + min(_avoidance_scheduler_penalty_cap(), suppression_pressure))
    if stats.completed == 0 and stats.skipped >= 100:
        score *= 0.1
    return max(0.1, min(10.0, score))


def _avoidance_probe_candidate(
    profiles: list[TargetProfile],
    state: DiscoveryState,
    inflight_counts: dict[str, int],
    max_target_share: float,
) -> TargetProfile | None:
    interval = _avoidance_probe_interval()
    if interval <= 0:
        return None
    total_attempts = sum(_target_budget_attempts(state, profile.id) for profile in profiles)
    if total_attempts <= 0 or total_attempts % interval != 0:
        return None
    eligible_profiles = _target_budget_eligible_profiles(profiles, state, max_target_share)
    candidates = [
        profile
        for profile in eligible_profiles
        if _target_seeded_suppression_pressure(state, profile.id) > 0.0
    ]
    if not candidates:
        return None

    def rank(profile: TargetProfile) -> tuple[int, int, float, str]:
        stats = _target_stats(state, profile.id)
        return (
            inflight_counts.get(profile.id, 0),
            stats.submitted,
            -_target_seeded_suppression_pressure(state, profile.id),
            profile.id,
        )

    return min(candidates, key=rank)


def _target_seeded_suppression_pressure(state: DiscoveryState, target_id: str) -> float:
    hazard_pressure = 0.0
    for hazard in state.suppressed_case_hazards:
        hazard_target = _key_field(hazard, "target")
        if hazard_target and _same_or_derived_target(hazard_target, target_id):
            hazard_pressure += 0.35
    family_pressure = 0.0
    target_family = _target_family(target_id)
    for family in state.suppressed_case_families:
        family_target = _key_field(family, "target")
        if family_target and (
            _same_or_derived_target(family_target, target_id)
            or _same_or_derived_target(family_target, target_family)
        ):
            family_pressure += 0.75
    semantic_pressure = 0.0
    prefix = f"{target_id}|"
    family_prefix = f"{target_family}|"
    for semantic_key in state.suppressed_semantic_shapes:
        if semantic_key.startswith(prefix) or semantic_key.startswith(family_prefix):
            semantic_pressure += 0.10
    return hazard_pressure + family_pressure + min(4.0, semantic_pressure)


def _key_field(key: str, field_name: str) -> str:
    prefix = f"{field_name}:"
    for part in key.split("|"):
        if part.startswith(prefix):
            return part.removeprefix(prefix)
    return ""


def _same_or_derived_target(left: str, right: str) -> bool:
    if left == right:
        return True
    return left.startswith(f"{right}_") or right.startswith(f"{left}_")


def _short_signature_label(signature: str) -> str:
    label = signature
    if label.startswith("SUMMARY: AddressSanitizer: "):
        label = label.removeprefix("SUMMARY: AddressSanitizer: ")
    label = label.replace(" ", "-").replace("/", "_")
    return label[:96]


def _target_stats_summary(state: DiscoveryState) -> dict[str, dict[str, int]]:
    return {
        target_id: asdict(stats)
        for target_id, stats in sorted(state.target_stats.items())
    }


def _write_discovery_state(root: Path, state: DiscoveryState) -> None:
    payload = {
        "runtime_skip_enabled": state.runtime_skip_enabled,
        "crash_skip_after": state.crash_skip_after,
        "hazard_skip_after": state.hazard_skip_after,
        "semantic_skip_after": state.semantic_skip_after,
        "generalized_skip_enabled": state.generalized_skip_enabled,
        "family_skip_after": state.family_skip_after,
        "runtime_suppressed_shapes": len(state.suppressed_case_shapes),
        "runtime_suppressed_hazards": len(state.suppressed_case_hazards),
        "runtime_suppressed_families": len(state.suppressed_case_families),
        "runtime_suppressed_semantic_shapes": len(state.suppressed_semantic_shapes),
        "suppressed_case_shapes": [
            {"shape": shape, "signature": signature}
            for shape, signature in sorted(state.suppressed_case_shapes.items())
        ],
        "suppressed_semantic_shapes": [
            {"semantic": semantic, "signature": signature}
            for semantic, signature in sorted(state.suppressed_semantic_shapes.items())
        ],
        "suppressed_case_hazards": [
            {"hazard": hazard, "signature": signature}
            for hazard, signature in sorted(state.suppressed_case_hazards.items())
        ],
        "suppressed_case_families": [
            {"family": family, "signature": signature}
            for family, signature in sorted(state.suppressed_case_families.items())
        ],
        "target_stats": _target_stats_summary(state),
        "scheduler_credit": {
            target_id: round(credit, 6)
            for target_id, credit in sorted(state.scheduler_credit.items())
        },
    }
    (root / "discovery_state.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _warm_template_synth_cache(profiles: list[TargetProfile]) -> None:
    warmed_ppd: set[tuple[str, int]] = set()
    warmed_document: set[tuple[str, int]] = set()
    for profile in profiles:
        ppd_period = PPD_PERIODS.get(profile.ppd_kind, 1)
        for case_id in range(ppd_period):
            key = (profile.ppd_kind, case_id)
            if key not in warmed_ppd:
                make_ppd(profile.ppd_kind, case_id)
                warmed_ppd.add(key)
        document_period = DOCUMENT_PERIODS.get(profile.document_kind, 1)
        for case_id in range(document_period):
            key = (profile.id, profile.document_kind, case_id)
            if key not in warmed_document:
                make_document(profile.document_kind, case_id, target_id=profile.id)
                warmed_document.add(key)


def _prune_case_artifacts(result: CaseResult, extra: dict[str, Any] | None) -> bool:
    if result.crashed or result.timed_out:
        return False
    if extra and extra.get("retained_for_coverage"):
        return False
    path = Path(result.work_dir)
    if not path.exists():
        return False
    shutil.rmtree(path)
    return True


def _run_dir_limit_reached(root: Path, max_run_bytes: int) -> bool:
    return bool(max_run_bytes and _run_dir_size_bytes(root) >= max_run_bytes)


def _run_dir_size_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return total
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def coverage_skip_reason(profile: TargetProfile, case_id: int) -> str:
    if _skip_short_image_aborts_enabled() and profile.document_kind == "image_feedback_sweep":
        image = image_feedback_instance(case_id)
        if image.objective == "short_payload" and image.image_format.startswith("png"):
            return "low-value-short-png-libpng-abort"
    if "rastertoescpx" in profile.id and profile.document_kind == "cups_raster_general_sweep":
        case_mod = case_id % len(RASTER_GENERAL_CASES)
        if case_mod in RASTERTOESCPX_DOTROWSTEP_ZERO_MODS:
            return "known-rastertoescpx-dotrowstep-zero-fpe"
    if "pwg_to_raster" in profile.id and profile.ppd_kind == "pwg_resolution_general":
        dpi = GENERAL_RESOLUTIONS[case_id % len(GENERAL_RESOLUTIONS)]
        if dpi == 65536:
            return "known-libppd-65536dpi-fpe"
    return ""


def _skip_short_image_aborts_enabled() -> bool:
    return _env_flag("SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS")


def _llvm_profiles_enabled() -> bool:
    return _env_flag("SMT_FUZZER_ENABLE_LLVM_PROFILES")


def _template_cycle_epochs() -> int:
    value = os.environ.get("SMT_FUZZER_IMAGE_CYCLE_EPOCHS") or os.environ.get("SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS", "1")
    try:
        return max(1, min(64, int(value)))
    except ValueError:
        return 1


def _hazard_skip_after() -> int:
    value = os.environ.get("SMT_FUZZER_HAZARD_SKIP_AFTER", "0")
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _semantic_skip_after() -> int:
    value = os.environ.get("SMT_FUZZER_SEMANTIC_SKIP_AFTER", "0")
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _avoidance_probe_interval() -> int:
    value = os.environ.get("SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL", "0")
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _avoidance_skip_probe_rate() -> float:
    value = os.environ.get("SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE", "0")
    try:
        return max(0.0, min(1.0, float(value)))
    except ValueError:
        return 0.0


def _avoidance_scheduler_penalty_cap() -> float:
    value = os.environ.get("SMT_FUZZER_AVOIDANCE_SCHEDULER_PENALTY_CAP", "2.0")
    try:
        return max(0.0, min(12.0, float(value)))
    except ValueError:
        return 2.0


def _scheduler_crash_penalty_disabled() -> bool:
    return _env_flag("SMT_FUZZER_DISABLE_SCHEDULER_CRASH_PENALTY")


def _legacy_skip_state_enabled() -> bool:
    return os.environ.get("SMT_FUZZER_LOAD_LEGACY_SKIP_STATE", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _skip_warm_template_cache() -> bool:
    return _env_flag("SMT_FUZZER_SKIP_WARM_TEMPLATE_CACHE")


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _count_llvm_profile_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob("*.profraw") if path.is_file() and path.stat().st_size > 0)


def run_cupstestppd(ppd_path: Path, output_path: Path) -> bool:
    completed = subprocess.run(
        ["cupstestppd", "-W", "none", str(ppd_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output_path.write_text(completed.stdout, encoding="utf-8")
    return completed.returncode == 0


def list_filters(profile: TargetProfile, ppd_path: Path, document_path: Path, stderr_path: Path) -> list[str]:
    if profile.executor == "direct_filter":
        return profile.expected_filters
    try:
        completed = subprocess.run(
            [
                "/usr/sbin/cupsfilter",
                "--list-filters",
                "-p",
                str(ppd_path),
                "-e",
                "-i",
                profile.input_mime,
                "-m",
                profile.output_mime,
                str(document_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stderr_path.write_text(str(exc), encoding="utf-8")
        return []
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def build_job_options(profile: TargetProfile, case_id: int) -> str:
    if profile.executor != "direct_filter" or not _job_options_enabled():
        return ""
    slot = case_id % JOB_OPTION_PERIOD
    page_size = PAGE_SIZES[slot % len(PAGE_SIZES)][0]
    color_model = JOB_COLOR_MODELS[(slot // len(PAGE_SIZES)) % len(JOB_COLOR_MODELS)]
    quality = JOB_PRINT_QUALITIES[(slot // 7) % len(JOB_PRINT_QUALITIES)]
    media = JOB_MEDIA_TYPES[(slot // 11) % len(JOB_MEDIA_TYPES)]
    duplex = JOB_DUPLEX_MODES[(slot // 13) % len(JOB_DUPLEX_MODES)]
    resolution = _job_resolution(profile, slot)
    options: list[tuple[str, str]] = [
        ("PageSize", page_size),
        ("PageRegion", page_size),
        ("ColorModel", color_model),
        ("PrintQuality", quality),
        ("MediaType", media),
        ("Duplex", duplex),
    ]
    if resolution:
        options.append(("Resolution", resolution))
    if _target_family(profile.id).startswith(("image_to_", "pdf_to_", "postscript_to_", "text_to_")):
        options.extend(
            [
                ("fit-to-page", "true" if (slot // 17) % 2 else "false"),
                ("scaling", JOB_SCALING_VALUES[(slot // 19) % len(JOB_SCALING_VALUES)]),
                ("natural-scaling", JOB_NATURAL_SCALING_VALUES[(slot // 23) % len(JOB_NATURAL_SCALING_VALUES)]),
                ("orientation-requested", JOB_ORIENTATIONS[(slot // 29) % len(JOB_ORIENTATIONS)]),
                ("print-scaling", JOB_PRINT_SCALING[(slot // 31) % len(JOB_PRINT_SCALING)]),
            ]
        )
    return " ".join(f"{key}={value}" for key, value in options)


def _job_resolution(profile: TargetProfile, slot: int) -> str:
    if profile.ppd_kind.startswith("pwg_resolution"):
        if profile.ppd_kind == "pwg_resolution_general":
            dpi = GENERAL_RESOLUTIONS[slot % len(GENERAL_RESOLUTIONS)]
        elif profile.ppd_kind == "pwg_resolution_sweep":
            dpi = GENERIC_RESOLUTIONS[slot % len(GENERIC_RESOLUTIONS)]
        else:
            dpi = COVERAGE_RESOLUTIONS[slot % len(COVERAGE_RESOLUTIONS)]
        return f"{dpi}x{dpi}dpi"
    if any(token in profile.id for token in ("raster", "image", "pdf", "postscript")):
        dpi = COVERAGE_RESOLUTIONS[slot % len(COVERAGE_RESOLUTIONS)]
        return f"{dpi}x{dpi}dpi"
    return ""


def _job_options_enabled() -> bool:
    return os.environ.get("SMT_FUZZER_DISABLE_JOB_OPTIONS", "").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }


def build_command(
    profile: TargetProfile,
    ppd_path: Path,
    document_path: Path,
    *,
    job_options: str = "",
) -> list[str]:
    if profile.executor == "cupsfilter":
        return [
            "/usr/sbin/cupsfilter",
            "-p",
            str(ppd_path),
            "-e",
            "-i",
            profile.input_mime,
            "-m",
            profile.output_mime,
            str(document_path),
        ]
    if profile.executor == "direct_filter":
        return [profile.filter_binary, "1", "smt", "smt", "1", job_options, str(document_path)]
    raise ValueError(f"unknown executor: {profile.executor}")


def format_command(profile: TargetProfile, ppd_path: Path, command: list[str], case_dir: Path | None = None) -> str:
    if profile.executor == "direct_filter":
        overrides = build_env_overrides(profile, ppd_path, case_dir)
        prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in overrides.items())
        return f"{prefix} {shlex.join(command)}"
    return shlex.join(command)


def build_env(profile: TargetProfile, ppd_path: Path, case_dir: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update(build_env_overrides(profile, ppd_path, case_dir))
    return env


def build_env_overrides(profile: TargetProfile, ppd_path: Path, case_dir: Path | None = None) -> dict[str, str]:
    if profile.executor != "direct_filter":
        return {}
    overrides = {"PPD": str(ppd_path), "SMT_FUZZER_TARGET_ID": profile.id}
    if _uses_local_cups_filter(profile.filter_binary):
        overrides["LD_LIBRARY_PATH"] = _local_filter_library_path()
        overrides["ASAN_OPTIONS"] = os.environ.get(
            "ASAN_OPTIONS",
            "abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86",
        )
    trace_lib = _dynamic_compare_trace_lib()
    if trace_lib and case_dir is not None and _dynamic_compare_trace_enabled(case_dir):
        overrides["SMT_FUZZER_COMPARE_TRACE"] = str(case_dir / "compare_trace.tsv")
        overrides["SMT_FUZZER_COMPARE_TRACE_LIMIT"] = os.environ.get("SMT_FUZZER_COMPARE_TRACE_LIMIT", "256")
        inherited_preload = os.environ.get("LD_PRELOAD", "")
        overrides["LD_PRELOAD"] = trace_lib if not inherited_preload else f"{trace_lib}:{inherited_preload}"
        asan_options = overrides.get("ASAN_OPTIONS", os.environ.get("ASAN_OPTIONS", ""))
        if asan_options:
            overrides["ASAN_OPTIONS"] = _append_asan_option(asan_options, "verify_asan_link_order=0")
    if _llvm_profiles_enabled():
        if case_dir is not None:
            overrides["LLVM_PROFILE_FILE"] = str(case_dir / "llvm.profraw")
        else:
            profile_dir = os.environ.get("SMT_FUZZER_LLVM_PROFILE_DIR", "work/llvm-profraw")
            Path(profile_dir).mkdir(parents=True, exist_ok=True)
            overrides["LLVM_PROFILE_FILE"] = str(Path(profile_dir) / f"{profile.id}-%p-%m.profraw")
    elif os.environ.get("SMT_FUZZER_LLVM_PROFILE_DIR"):
        profile_dir = os.environ["SMT_FUZZER_LLVM_PROFILE_DIR"]
        Path(profile_dir).mkdir(parents=True, exist_ok=True)
        overrides["LLVM_PROFILE_FILE"] = str(Path(profile_dir) / f"{profile.id}-%p-%m.profraw")
    return overrides


def _dynamic_compare_trace_lib() -> str:
    value = os.environ.get("SMT_FUZZER_DYNAMIC_COMPARE_TRACE_LIB", "").strip()
    if not value:
        return ""
    path = Path(value)
    return str(path) if path.exists() else ""


def _dynamic_compare_trace_enabled(case_dir: Path) -> bool:
    case_id = _case_id_from_dir(case_dir)
    max_cases = _positive_int_env("SMT_FUZZER_DYNAMIC_COMPARE_TRACE_MAX_CASES", 0)
    if max_cases and case_id >= max_cases:
        return False
    every = _positive_int_env("SMT_FUZZER_DYNAMIC_COMPARE_TRACE_EVERY", 1)
    return case_id % every == 0


def _case_id_from_dir(case_dir: Path) -> int:
    match = re.search(r"case-(\d+)$", case_dir.name)
    if not match:
        return 0
    return int(match.group(1))


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def _append_asan_option(options: str, option: str) -> str:
    key = option.split("=", 1)[0]
    parts = [part for part in options.split(":") if part]
    if any(part == key or part.startswith(f"{key}=") for part in parts):
        return options
    return ":".join(parts + [option])


def _uses_local_cups_filter(filter_binary: str) -> bool:
    return filter_binary.startswith("/data/pre-gsoc/cups-filters")


def _local_filter_library_path() -> str:
    paths: list[str] = []
    _append_env_or_default_dirs(
        paths,
        "SMT_FUZZER_LIBPPD_ASAN",
        [
            "/data/pre-gsoc/libppd-origin-latest/.libs",
            "/data/pre-gsoc/libppd/.libs",
        ],
    )
    _append_env_or_default_dirs(
        paths,
        "SMT_FUZZER_LIBCUPSFILTERS_ASAN",
        [
            "/data/pre-gsoc/libcupsfilters-master-asan/.libs",
            "/data/pre-gsoc/libcupsfilters/.libs",
        ],
    )
    _append_env_or_default_dirs(
        paths,
        "SMT_FUZZER_PDFIO_LIB",
        [
            "/data/pre-gsoc/env/pdfio-install/lib",
        ],
    )
    inherited = os.environ.get("LD_LIBRARY_PATH", "")
    if inherited:
        paths.extend(inherited.split(":"))
    return ":".join(_dedupe_paths(paths))


def _append_env_or_default_dirs(paths: list[str], env_name: str, defaults: list[str]) -> None:
    env_value = os.environ.get(env_name)
    if env_value:
        paths.extend(env_value.split(":"))
        return
    for candidate in defaults:
        if Path(candidate).exists():
            paths.append(candidate)
            return


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        result.append(path)
    return result


def classify(
    profile: TargetProfile,
    stderr_text: str,
    returncode: int | None,
    timed_out: bool,
) -> tuple[bool, str]:
    text = stderr_text.lower()
    if timed_out:
        return False, "timeout"
    if "asan runtime does not come first" in text:
        return False, "infra-asan-runtime-order"
    if profile.oracle == "rastertopclx_signal_11" and "rastertopclx" in text and "crashed on signal 11" in text:
        return True, "rastertopclx signal 11"
    if "addresssanitizer" in text or "segmentation fault" in text or "crashed on signal" in text:
        return True, "stderr crash/sanitizer"
    if returncode is not None and returncode < 0:
        return True, f"signal {-returncode}"
    if returncode in {86, 134, 139}:
        return True, f"returncode {returncode}"
    if profile.oracle == "reached_only":
        return False, "reached_only"
    return False, ""


def _process_discovery_result(
    result: CaseResult,
    root: Path,
    discovery_mode: str,
    state: DiscoveryState,
) -> dict[str, Any]:
    if discovery_mode != "coverage":
        _update_target_after_result(state, result, retained=False, new_feature_count=0, new_signature=None)
        return {}

    features = extract_case_features(result)
    stderr_path = Path(result.stderr_path)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    shape_bundle = build_result_shape_bundle(result, stderr_text)
    features.update(shape_feature_tokens(shape_bundle))
    new_features = sorted(features - state.seen_features)
    state.seen_features.update(features)
    retained = bool(new_features)
    if retained:
        state.retained_cases += 1
        _retain_interesting_case(root, result, features, new_features)

    extra: dict[str, Any] = {
        "coverage_feature_count": len(features),
        "new_feature_count": len(new_features),
        "retained_for_coverage": retained,
        "semantic_shape": compact_shape_record(shape_bundle),
        "semantic_runtime_key": semantic_runtime_key(result.target_id, str(shape_bundle.get("semantic_input_hash") or "")),
    }
    if retained:
        extra["new_features"] = new_features[:32]

    new_signature: bool | None = None
    if result.crashed:
        signature = compute_crash_signature(asdict(result), stderr_text)
        new_signature = signature not in state.seen_crash_signatures
        state.seen_crash_signatures.add(signature)
        if new_signature:
            state.unique_crashes += 1
        else:
            state.repeat_crashes += 1
        runtime_suppressed = False
        if state.runtime_skip_enabled:
            runtime_suppressed = record_runtime_crash_suppression(
                state,
                TargetProfile(
                    id=result.target_id,
                    description=result.target_description,
                    ppd_kind=result.ppd_kind,
                    document_kind=result.document_kind,
                    executor="",
                    input_mime="",
                    output_mime="",
                    expected_filters=[],
                    cases=0,
                    oracle="",
                    filter_binary="",
                ),
                result.case_id,
                signature,
            )
            semantic_runtime_suppressed = record_semantic_crash_suppression(
                state,
                result,
                shape_bundle,
                signature,
                retained=retained,
            )
        else:
            semantic_runtime_suppressed = False
        _record_quarantine(root, result, signature, new_signature)
        extra.update(
            {
                "crash_signature": signature,
                "new_crash_signature": new_signature,
                "quarantined_repeat": not new_signature,
                "runtime_suppressed_shape": runtime_suppressed,
                "runtime_suppressed_semantic_shape": semantic_runtime_suppressed,
            }
        )

    _update_target_after_result(
        state,
        result,
        retained=retained,
        new_feature_count=len(new_features),
        new_signature=new_signature,
    )
    return extra


def _update_target_after_result(
    state: DiscoveryState,
    result: CaseResult,
    *,
    retained: bool,
    new_feature_count: int,
    new_signature: bool | None,
) -> None:
    stats = _target_stats(state, result.target_id)
    stats.completed += 1
    state.completed_cases += 1
    if retained:
        stats.retained_cases += 1
    stats.new_features += new_feature_count
    if result.timed_out:
        stats.timeouts += 1
    if result.crashed:
        stats.crashes += 1
        if new_signature is True:
            stats.unique_crashes += 1
        elif new_signature is False:
            stats.repeat_crashes += 1


def extract_case_features(result: CaseResult) -> set[str]:
    features = {
        f"target:{result.target_id}",
        f"ppd:{result.ppd_kind}",
        f"document:{result.document_kind}",
        f"oracle:{result.oracle or 'none'}",
        f"returncode:{result.returncode}",
        f"reached:{result.reached_expected_filter}",
    }
    if result.timed_out:
        features.add("timeout")
    if result.crashed:
        features.add("crash")
    features.update(_job_option_features(result.job_options))

    stderr_path = Path(result.stderr_path)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    features.update(_stderr_features(stderr_text))
    features.update(_document_header_features(Path(result.document_path)))
    features.update(_llvm_profile_features(result))
    return features


def _job_option_features(options: str) -> set[str]:
    if not options:
        return {"job-options:empty"}
    features = {"job-options:present"}
    try:
        parts = shlex.split(options)
    except ValueError:
        parts = options.split()
        features.add("job-options:parse-error")
    for part in parts:
        if "=" not in part:
            features.add(f"job-option:{part}")
            continue
        key, value = part.split("=", 1)
        if not key:
            continue
        features.add(f"job-option-key:{key}")
        if value:
            features.add(f"job-option:{key}={value}")
    return features


def _stderr_features(stderr_text: str) -> set[str]:
    features: set[str] = set()
    state_markers = (
        "cffilterimagetopdf:",
        "cffilterimagetoraster:",
        "ppdfilterimagetops",
        "before scaling:",
        "using portrait orientation",
        "using landscape orientation",
        "xpages =",
        "ypages =",
        "xposition=",
        "yposition=",
        "pageleft=",
        "pageright=",
        "pagewidth=",
        "pagebottom=",
        "pagetop=",
        "pagelength=",
        "cupswidth =",
        "cupsheight =",
        "cupsbitspercolor =",
        "cupsbitsperpixel =",
        "cupsbytesperline =",
        "cupscolororder =",
        "cupscolorspace =",
        "img->colorspace =",
        "orientation:",
        "formatting page",
    )
    for raw_line in stderr_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "addresssanitizer" in lowered:
            features.add("stderr:asan")
        if line.startswith("SUMMARY:"):
            features.add("stderr:" + line)
        if "fpe" in lowered:
            features.add("stderr:fpe")
        if "job completed" in lowered:
            features.add("stderr:job-completed")
        if "no page printed" in lowered:
            features.add("stderr:no-page-printed")
        if "not an integer multiple" in lowered:
            features.add("stderr:resolution-not-multiple")
        if "reducing by factor" in lowered:
            features.add("stderr:resolution-reducing")
            features.add("stderr:" + _normalize_numeric_feature(line))
        if "raising by factor" in lowered:
            features.add("stderr:resolution-raising")
            features.add("stderr:" + _normalize_numeric_feature(line))
        if "input color mode" in lowered:
            features.add("stderr:" + line)
        if "dotrowstep" in lowered or "dotrowcount" in lowered or "dotbuffer" in lowered:
            features.add("stderr:" + _normalize_numeric_feature(line))
        if line.startswith("PAGE:") or line.startswith("INFO: Finished page"):
            features.add("stderr:" + line)
        if any(marker in lowered for marker in state_markers):
            features.add("stderr-state:" + _normalize_numeric_feature(line))
    return features


def _normalize_numeric_feature(line: str) -> str:
    return re.sub(r"(?<![A-Za-z])[-+]?(?:\d+\.\d+|\d+)", "#", line)


def _llvm_profile_features(result: CaseResult) -> set[str]:
    profile_path = Path(result.work_dir) / "llvm.profraw"
    if not profile_path.exists():
        return set()
    try:
        size = profile_path.stat().st_size
    except OSError:
        return set()
    if size <= 0:
        return set()
    return {
        "llvm-profraw:present",
        f"llvm-profraw-size:{_size_bucket(size)}",
    }


def _size_bucket(size: int) -> str:
    if size < 1024:
        return "lt1k"
    if size < 16 * 1024:
        return "1k-16k"
    if size < 256 * 1024:
        return "16k-256k"
    if size < 1024 * 1024:
        return "256k-1m"
    return "ge1m"


def _document_header_features(document_path: Path) -> set[str]:
    if not document_path.exists():
        return set()
    data = document_path.read_bytes()
    if data.startswith(b"%PDF-"):
        return _pdf_features(data)
    if data.startswith(b"%!PS"):
        return _postscript_features(data)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return _png_features(data)
    if len(data) >= 2 and data[:1] == b"P" and data[1:2] in {b"1", b"2", b"3", b"4", b"5", b"6"}:
        return _pnm_features(data)
    if data.startswith(b"#CUPS-COMMAND"):
        return {
            "doc-format:cups-command",
            f"doc-size:{len(data)}",
            f"doc-lines:{data.count(bytes([10]))}",
        }
    sync = data[:4].decode("latin1", errors="replace")
    if sync in {"3SaR", "2SaR"}:
        return _raster_features(data, sync)
    if data.startswith(b"%") or data[:32].isascii():
        return {
            "doc-format:text-like",
            f"doc-size:{len(data)}",
            f"doc-lines:{data.count(bytes([10]))}",
        }
    if len(data) < 4 + 424:
        return {f"doc-size:{len(data)}"}
    return {f"doc-format:binary", f"doc-sync:{sync}", f"doc-size:{len(data)}"}


def _raster_features(data: bytes, sync: str) -> set[str]:
    if len(data) < 4 + 424:
        return {f"doc-sync:{sync}", "doc-header:short", f"doc-size:{len(data)}"}
    header = data[4 : 4 + 1796]
    try:
        x_res = _u32(header, OFF_HW_RESOLUTION)
        y_res = _u32(header, OFF_HW_RESOLUTION + 4)
        width = _u32(header, OFF_CUPS_WIDTH)
        height = _u32(header, OFF_CUPS_HEIGHT)
        bpp = _u32(header, OFF_CUPS_BITS_PER_PIXEL)
        bpl = _u32(header, OFF_CUPS_BYTES_PER_LINE)
        order = _u32(header, OFF_CUPS_COLOR_ORDER)
        color_space = _u32(header, OFF_CUPS_COLOR_SPACE)
        compression = _u32(header, OFF_CUPS_COMPRESSION)
        row_count = _u32(header, OFF_CUPS_ROW_COUNT)
    except struct.error:
        return {f"doc-sync:{sync}", "doc-header:short"}
    return {
        f"doc-sync:{sync}",
        f"doc-res:{x_res}x{y_res}",
        f"doc-size:{width}x{height}",
        f"doc-bpp:{bpp}",
        f"doc-bpl-bucket:{_bucket(bpl)}",
        f"doc-color-order:{order}",
        f"doc-color-space:{color_space}",
        f"doc-compression:{compression}",
        f"doc-row-count:{row_count}",
    }


def _pdf_features(data: bytes) -> set[str]:
    return {
        "doc-format:pdf",
        f"doc-size:{len(data)}",
        f"doc-pdf-version:{data[:8].decode('latin1', errors='replace')}",
        f"doc-pdf-objects:{data.count(b' obj')}",
        f"doc-pdf-streams:{data.count(b'stream')}",
    }


def _postscript_features(data: bytes) -> set[str]:
    return {
        "doc-format:postscript",
        f"doc-size:{len(data)}",
        f"doc-lines:{data.count(bytes([10]))}",
        f"doc-ps-showpage:{data.count(b'showpage')}",
    }


def _png_features(data: bytes) -> set[str]:
    if len(data) < 33 or data[12:16] != b"IHDR":
        return {"doc-format:png", "doc-png:short", f"doc-size:{len(data)}"}
    width, height = struct.unpack(">II", data[16:24])
    bit_depth = data[24]
    color_type = data[25]
    return {
        "doc-format:png",
        f"doc-size:{len(data)}",
        f"doc-image-size:{width}x{height}",
        f"doc-png-bit-depth:{bit_depth}",
        f"doc-png-color-type:{color_type}",
    }


def _pnm_features(data: bytes) -> set[str]:
    tokens = []
    for raw_line in data.splitlines():
        line = raw_line.split(b"#", 1)[0].strip()
        if not line:
            continue
        tokens.extend(line.split())
        if len(tokens) >= 4:
            break
    magic = tokens[0].decode("ascii", errors="replace") if tokens else "P?"
    width = tokens[1].decode("ascii", errors="replace") if len(tokens) > 1 else "?"
    height = tokens[2].decode("ascii", errors="replace") if len(tokens) > 2 else "?"
    return {
        "doc-format:pnm",
        f"doc-size:{len(data)}",
        f"doc-pnm-magic:{magic}",
        f"doc-image-size:{width}x{height}",
    }


def _u32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]


def _bucket(value: int) -> str:
    if value < 8:
        return "lt8"
    if value < 64:
        return "lt64"
    if value < 512:
        return "lt512"
    if value < 4096:
        return "lt4096"
    return "ge4096"


def _retain_interesting_case(root: Path, result: CaseResult, features: set[str], new_features: list[str]) -> None:
    dest = root / "corpus" / "interesting" / result.target_id / f"case-{result.case_id:06d}"
    dest.mkdir(parents=True, exist_ok=True)
    for source_name in ["candidate.ppd", "command.txt", "stderr.txt", "meta.json"]:
        source = Path(result.work_dir) / source_name
        if source.exists():
            shutil.copy2(source, dest / source_name)
    document_source = Path(result.document_path)
    if document_source.exists():
        shutil.copy2(document_source, dest / document_source.name)
    (dest / "features.json").write_text(
        json.dumps(
            {
                "features": sorted(features),
                "new_features": new_features,
                "source_work_dir": result.work_dir,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _record_quarantine(root: Path, result: CaseResult, signature: str, new_signature: bool) -> None:
    quarantine = root / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)
    record = {
        "target_id": result.target_id,
        "case_id": result.case_id,
        "signature": signature,
        "new_signature": new_signature,
        "work_dir": result.work_dir,
        "command_line": result.command_line,
        "job_options": result.job_options,
        "stderr_path": result.stderr_path,
    }
    with (quarantine / ("unique.jsonl" if new_signature else "repeats.jsonl")).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    if new_signature:
        dest = quarantine / "unique" / f"{result.target_id}-case-{result.case_id:06d}"
        dest.mkdir(parents=True, exist_ok=True)
        for source_name in ["candidate.ppd", "command.txt", "stderr.txt", "meta.json"]:
            source = Path(result.work_dir) / source_name
            if source.exists():
                shutil.copy2(source, dest / source_name)
        document_source = Path(result.document_path)
        if document_source.exists():
            shutil.copy2(document_source, dest / document_source.name)


def _write_run_records(result: CaseResult, timeline, commands, extra: dict[str, Any] | None = None) -> None:
    commands.write(f"{result.target_id} case-{result.case_id:04d}: {result.command_line}\n")
    commands.flush()
    record = {
        "target_id": result.target_id,
        "case_id": result.case_id,
        "ppd_kind": result.ppd_kind,
        "document_kind": result.document_kind,
        "document_description": result.document_description,
        "command_line": result.command_line,
        "job_options": result.job_options,
        "env_overrides": result.env_overrides,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "crashed": result.crashed,
        "oracle": result.oracle,
        "duration_ms": result.duration_ms,
        "cupstestppd_ok": result.cupstestppd_ok,
        "reached_expected_filter": result.reached_expected_filter,
        "filters": result.filters,
        "work_dir": result.work_dir,
        "stderr_path": result.stderr_path,
        "stderr_tail": result.stderr_tail,
    }
    if extra:
        record.update(extra)
    timeline.write(json.dumps(record, sort_keys=True) + "\n")
    timeline.flush()


def _write_skip_record(
    profile: TargetProfile,
    case_id: int,
    case_dir: Path,
    skip_reason: str,
    timeline,
    commands,
) -> None:
    commands.write(f"{profile.id} case-{case_id:04d}: SKIP {skip_reason}\n")
    commands.flush()
    timeline.write(
        json.dumps(
            {
                "target_id": profile.id,
                "case_id": case_id,
                "ppd_kind": profile.ppd_kind,
                "document_kind": profile.document_kind,
                "skipped": True,
                "skip_reason": skip_reason,
                "crashed": False,
                "timed_out": False,
                "oracle": "skipped-known-shallow-crash",
                "work_dir": str(case_dir),
            },
            sort_keys=True,
        )
        + "\n"
    )
    timeline.flush()


def _tail_lines(text: str, limit: int) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-limit:]
