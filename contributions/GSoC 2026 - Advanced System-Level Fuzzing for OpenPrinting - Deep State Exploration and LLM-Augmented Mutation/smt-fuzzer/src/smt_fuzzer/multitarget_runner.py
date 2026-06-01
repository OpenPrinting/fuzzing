from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import shlex
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .crash_dedup import compute_crash_signature
from .document_harness import (
    OFF_CUPS_BITS_PER_PIXEL,
    OFF_CUPS_BYTES_PER_LINE,
    OFF_CUPS_COLOR_ORDER,
    OFF_CUPS_COLOR_SPACE,
    OFF_CUPS_COMPRESSION,
    OFF_CUPS_HEIGHT,
    OFF_CUPS_ROW_COUNT,
    OFF_CUPS_WIDTH,
    OFF_HW_RESOLUTION,
    RASTER_GENERAL_CASES,
    make_document,
)
from .ppd_templates import GENERAL_RESOLUTIONS, make_ppd


RASTERTOESCPX_DOTROWSTEP_ZERO_MODS = {3, 4, 6, 8, 9, 11}


@dataclass
class DiscoveryState:
    seen_features: set[str] = field(default_factory=set)
    seen_crash_signatures: set[str] = field(default_factory=set)
    retained_cases: int = 0
    unique_crashes: int = 0
    repeat_crashes: int = 0


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
    env_overrides: dict[str, str]
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
    targets: int
    cases: int
    crashes: int
    reached: int
    valid_ppds: int
    timeouts: int
    skipped: int
    skip_counts: dict[str, int]
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
            "targets": self.targets,
            "cases": self.cases,
            "crashes": self.crashes,
            "reached": self.reached,
            "valid_ppds": self.valid_ppds,
            "timeouts": self.timeouts,
            "skipped": self.skipped,
            "skip_counts": self.skip_counts,
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
    run_command: str = "",
    capture_stdout: bool = True,
    discovery_mode: str = "crash",
) -> MultiTargetSummary:
    profiles = load_profiles(config_path)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    root = Path(work_root) / run_id
    root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    results: list[CaseResult] = []
    skipped = 0
    skip_counts: dict[str, int] = {}
    discovery_state = DiscoveryState()
    manifest = {
        "run_id": run_id,
        "work_dir": str(root),
        "config_path": str(config_path),
        "workers": workers,
        "cases_per_target": cases_per_target,
        "duration_sec": duration_sec,
        "timeout_sec": timeout_sec,
        "run_command": run_command,
        "capture_stdout": capture_stdout,
        "discovery_mode": discovery_mode,
        "guidance_policy": (
            "general-format-aware; weak public seeds only; no bug-specific payload dictionary; "
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
                f"workers={workers}",
                f"cases_per_target={cases_per_target}",
                f"duration_sec={duration_sec}",
                f"timeout_sec={timeout_sec}",
                f"capture_stdout={capture_stdout}",
                f"discovery_mode={discovery_mode}",
                f"run_command={run_command}",
                "guidance=general-format-aware",
                "",
            ]
        ),
        encoding="utf-8",
    )

    with timeline_path.open("a", encoding="utf-8") as timeline, commands_path.open("a", encoding="utf-8") as commands:
        if duration_sec is None:
            jobs: list[tuple[TargetProfile, int, Path]] = []
            for profile in profiles:
                count = cases_per_target if cases_per_target is not None else profile.cases
                for case_id in range(count):
                    case_dir = root / profile.id / f"case-{case_id:04d}"
                    skip_reason = coverage_skip_reason(profile, case_id) if discovery_mode == "coverage" else ""
                    if skip_reason:
                        skipped += 1
                        skip_counts[skip_reason] = skip_counts.get(skip_reason, 0) + 1
                        _write_skip_record(profile, case_id, case_dir, skip_reason, timeline, commands)
                        continue
                    jobs.append((profile, case_id, case_dir))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(run_case, profile, case_id, case_dir, timeout_sec, capture_stdout)
                    for profile, case_id, case_dir in jobs
                ]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    results.append(result)
                    extra = _process_discovery_result(result, root, discovery_mode, discovery_state)
                    _write_run_records(result, timeline, commands, extra)
        else:
            deadline = started + duration_sec
            next_case_ids = {profile.id: 0 for profile in profiles}
            profile_index = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures: set[concurrent.futures.Future[CaseResult]] = set()
                while time.monotonic() < deadline or futures:
                    while time.monotonic() < deadline and len(futures) < workers:
                        profile = profiles[profile_index % len(profiles)]
                        profile_index += 1
                        case_id = next_case_ids[profile.id]
                        next_case_ids[profile.id] += 1
                        case_dir = root / profile.id / f"case-{case_id:04d}"
                        skip_reason = coverage_skip_reason(profile, case_id) if discovery_mode == "coverage" else ""
                        if skip_reason:
                            skipped += 1
                            skip_counts[skip_reason] = skip_counts.get(skip_reason, 0) + 1
                            _write_skip_record(profile, case_id, case_dir, skip_reason, timeline, commands)
                            continue
                        futures.add(executor.submit(run_case, profile, case_id, case_dir, timeout_sec, capture_stdout))
                    if not futures:
                        break
                    done, futures = concurrent.futures.wait(
                        futures,
                        timeout=max(0.1, min(1.0, deadline - time.monotonic())),
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for future in done:
                        result = future.result()
                        results.append(result)
                        extra = _process_discovery_result(result, root, discovery_mode, discovery_state)
                        _write_run_records(result, timeline, commands, extra)

    results.sort(key=lambda item: (item.target_id, item.case_id))
    oracle_counts: dict[str, int] = {}
    for result in results:
        oracle_counts[result.oracle or "none"] = oracle_counts.get(result.oracle or "none", 0) + 1
    summary = MultiTargetSummary(
        run_id=run_id,
        work_dir=str(root),
        config_path=str(config_path),
        duration_budget_sec=duration_sec,
        elapsed_sec=round(time.monotonic() - started, 3),
        workers=workers,
        timeout_sec=timeout_sec,
        targets=len(profiles),
        cases=len(results),
        crashes=sum(1 for result in results if result.crashed),
        reached=sum(1 for result in results if result.reached_expected_filter),
        valid_ppds=sum(1 for result in results if result.cupstestppd_ok),
        timeouts=sum(1 for result in results if result.timed_out),
        skipped=skipped,
        skip_counts=dict(sorted(skip_counts.items())),
        retained_cases=discovery_state.retained_cases,
        coverage_features=len(discovery_state.seen_features),
        unique_crashes=discovery_state.unique_crashes,
        repeat_crashes=discovery_state.repeat_crashes,
        oracle_counts=dict(sorted(oracle_counts.items())),
        results=results,
    )
    (root / "summary.json").write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "summary.concise.json").write_text(
        json.dumps(summary.concise_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
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
    document = make_document(profile.document_kind, case_id)
    document_path = case_dir / f"document{document.extension}"
    document_path.write_bytes(document.data)

    cupstestppd_ok = run_cupstestppd(ppd_path, case_dir / "cupstestppd.txt")
    filters = list_filters(profile, ppd_path, document_path, case_dir / "list_filters.stderr")
    reached = all(expected in filters for expected in profile.expected_filters)

    command = build_command(profile, ppd_path, document_path)
    command_line = format_command(profile, ppd_path, command)
    env_overrides = build_env_overrides(profile, ppd_path)
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
                env=build_env(profile, ppd_path),
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
        env_overrides=env_overrides,
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


def load_profiles(config_path: str | Path) -> list[TargetProfile]:
    data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    profiles = []
    for item in data.get("targets", []):
        profiles.append(
            TargetProfile(
                id=str(item["id"]),
                description=str(item.get("description", "")),
                ppd_kind=str(item["ppd_kind"]),
                document_kind=str(item["document_kind"]),
                executor=str(item["executor"]),
                input_mime=str(item.get("input_mime", "")),
                output_mime=str(item.get("output_mime", "printer/foo")),
                expected_filters=[str(value) for value in item.get("expected_filters", [])],
                cases=int(item.get("cases", 1)),
                oracle=str(item.get("oracle", "crash_or_signal")),
                filter_binary=expand_config_value(str(item.get("filter_binary", ""))),
            )
        )
    return profiles


def expand_config_value(value: str) -> str:
    filter_root = os.environ.get("SMT_FUZZER_FILTER_ROOT", "/usr/lib/cups/filter")
    expanded = value.replace("${SMT_FUZZER_FILTER_ROOT}", filter_root)
    return os.path.expanduser(os.path.expandvars(expanded))


def coverage_skip_reason(profile: TargetProfile, case_id: int) -> str:
    if "rastertoescpx" in profile.id and profile.document_kind == "cups_raster_general_sweep":
        case_mod = case_id % len(RASTER_GENERAL_CASES)
        if case_mod in RASTERTOESCPX_DOTROWSTEP_ZERO_MODS:
            return "known-rastertoescpx-dotrowstep-zero-fpe"
    if "pwg_to_raster" in profile.id and profile.ppd_kind == "pwg_resolution_general":
        dpi = GENERAL_RESOLUTIONS[case_id % len(GENERAL_RESOLUTIONS)]
        if dpi == 65536:
            return "known-libppd-65536dpi-fpe"
    return ""


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


def build_command(profile: TargetProfile, ppd_path: Path, document_path: Path) -> list[str]:
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
        return [profile.filter_binary, "1", "smt", "smt", "1", "", str(document_path)]
    raise ValueError(f"unknown executor: {profile.executor}")


def format_command(profile: TargetProfile, ppd_path: Path, command: list[str]) -> str:
    if profile.executor == "direct_filter":
        overrides = build_env_overrides(profile, ppd_path)
        prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in overrides.items())
        return f"{prefix} {shlex.join(command)}"
    return shlex.join(command)


def build_env(profile: TargetProfile, ppd_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(build_env_overrides(profile, ppd_path))
    return env


def build_env_overrides(profile: TargetProfile, ppd_path: Path) -> dict[str, str]:
    if profile.executor != "direct_filter":
        return {}
    overrides = {"PPD": str(ppd_path)}
    local_libs = os.environ.get("SMT_FUZZER_LD_LIBRARY_PATH", "")
    if not local_libs:
        lib_parts = [
            value
            for value in (
                os.environ.get("LIBCUPSFILTERS_ASAN"),
                os.environ.get("LIBPPD_ASAN"),
                os.environ.get("PDFIO_LIB"),
            )
            if value
        ]
        local_libs = ":".join(lib_parts)
    if local_libs:
        inherited = os.environ.get("LD_LIBRARY_PATH", "")
        overrides["LD_LIBRARY_PATH"] = f"{local_libs}:{inherited}" if inherited else local_libs
    if local_libs or os.environ.get("SMT_FUZZER_ASSUME_ASAN") == "1":
        overrides["ASAN_OPTIONS"] = os.environ.get(
            "ASAN_OPTIONS",
            "abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86",
        )
    profile_dir = os.environ.get("SMT_FUZZER_LLVM_PROFILE_DIR")
    if profile_dir:
        Path(profile_dir).mkdir(parents=True, exist_ok=True)
        overrides["LLVM_PROFILE_FILE"] = str(Path(profile_dir) / f"{profile.id}-%p-%m.profraw")
    return overrides


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
        return {}

    features = extract_case_features(result)
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
    }
    if retained:
        extra["new_features"] = new_features[:32]

    if result.crashed:
        stderr_text = Path(result.stderr_path).read_text(encoding="utf-8", errors="replace")
        signature = compute_crash_signature(asdict(result), stderr_text)
        new_signature = signature not in state.seen_crash_signatures
        state.seen_crash_signatures.add(signature)
        if new_signature:
            state.unique_crashes += 1
        else:
            state.repeat_crashes += 1
        _record_quarantine(root, result, signature, new_signature)
        extra.update(
            {
                "crash_signature": signature,
                "new_crash_signature": new_signature,
                "quarantined_repeat": not new_signature,
            }
        )

    return extra


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

    stderr_path = Path(result.stderr_path)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    features.update(_stderr_features(stderr_text))
    features.update(_document_header_features(Path(result.document_path)))
    return features


def _stderr_features(stderr_text: str) -> set[str]:
    features: set[str] = set()
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
    return features


def _normalize_numeric_feature(line: str) -> str:
    parts = []
    for token in line.split():
        if token.strip("[]:,").lstrip("-").isdigit():
            parts.append("#")
        else:
            parts.append(token)
    return " ".join(parts)


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
        "command_line": result.command_line,
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
