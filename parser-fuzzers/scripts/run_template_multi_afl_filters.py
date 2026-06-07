#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import struct
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


RASTER_DICT = "dictionaries/pwg_raster.dict"


@dataclass
class TargetPlan:
    target_id: str
    filter_binary: Path
    input_mime: str
    document_kind: str
    ppd_path: Path
    job_options: str
    seed_dir: Path
    out_dir: Path
    log_path: Path
    metrics_path: Path
    dictionary: Path | None
    seed_count: int
    fallback_seed: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run standard AFL++ for every parser target using template-generated documents as seeds.",
    )
    parser.add_argument("--template-run-dir", required=True, help="completed multitarget template/direct-filter run")
    parser.add_argument("--config", required=True, help="parser target YAML matching the template run")
    parser.add_argument("--output-root", required=True, help="AFL++ campaign output directory")
    parser.add_argument("--duration-sec", type=int, default=1800)
    parser.add_argument("--max-parallel", type=int, default=20)
    parser.add_argument("--seed-limit", type=int, default=768)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--max-campaign-gb", type=float, default=25.0)
    parser.add_argument("--min-free-gb", type=float, default=70.0)
    parser.add_argument("--monitor-interval-sec", type=int, default=60)
    parser.add_argument("--ld-library-path", default="")
    parser.add_argument("--afl-fuzz", default="afl-fuzz")
    parser.add_argument("--target-id", action="append", default=[], help="run only this target id; repeatable")
    parser.add_argument("--include-crashing-seeds", action="store_true")
    parser.add_argument("--no-preflight-seeds", action="store_false", dest="preflight_seeds")
    parser.add_argument("--preflight-timeout-sec", type=float, default=3.0)
    parser.add_argument("--upgrade-generated-seeds", type=int, default=0)
    parser.add_argument("--template-expansion-level", type=int, default=3)
    parser.add_argument("--template-cycle-epochs", type=int, default=4)
    parser.add_argument("--drop-nonviable-seeds", action="store_true")
    parser.set_defaults(preflight_seeds=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    template_run_dir = Path(args.template_run_dir)
    config_path = Path(args.config)
    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    if shutil.which(args.afl_fuzz) is None:
        raise SystemExit(f"AFL++ fuzzer not found in PATH: {args.afl_fuzz}")
    if not template_run_dir.is_dir():
        raise SystemExit(f"template run dir does not exist: {template_run_dir}")

    ld_library_path = args.ld_library_path or local_filter_library_path(root)
    configure_template_upgrade_env(args)
    plans = build_plans(
        root=root,
        config_path=config_path,
        template_run_dir=template_run_dir,
        output_root=output_root,
        seed_limit=args.seed_limit,
        include_crashing=args.include_crashing_seeds,
        target_ids=set(args.target_id or []),
        ld_library_path=ld_library_path,
        preflight_seeds=args.preflight_seeds,
        preflight_timeout_sec=args.preflight_timeout_sec,
        upgrade_generated_seeds=args.upgrade_generated_seeds,
        drop_nonviable_seeds=args.drop_nonviable_seeds or args.upgrade_generated_seeds > 0,
    )
    plan_path = output_root / "plans.json"
    plan_path.write_text(
        json.dumps([plan_to_json(plan) for plan in plans], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "template_run_dir": str(template_run_dir),
        "config": str(config_path),
        "output_root": str(output_root),
        "duration_sec": args.duration_sec,
        "max_parallel": args.max_parallel,
        "seed_limit": args.seed_limit,
        "timeout_ms": args.timeout_ms,
        "max_campaign_gb": args.max_campaign_gb,
        "min_free_gb": args.min_free_gb,
        "ld_library_path": ld_library_path,
        "targets": len(plans),
        "plans": str(plan_path),
        "upgrade_generated_seeds": args.upgrade_generated_seeds,
        "template_expansion_level": args.template_expansion_level,
        "template_cycle_epochs": args.template_cycle_epochs,
        "drop_nonviable_seeds": bool(args.drop_nonviable_seeds or args.upgrade_generated_seeds > 0),
    }
    (output_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({"event": "prepared", **manifest}, sort_keys=True), flush=True)
    return run_scheduler(
        plans=plans,
        args=args,
        ld_library_path=ld_library_path,
        output_root=output_root,
    )


def build_plans(
    *,
    root: Path,
    config_path: Path,
    template_run_dir: Path,
    output_root: Path,
    seed_limit: int,
    include_crashing: bool,
    target_ids: set[str],
    ld_library_path: str,
    preflight_seeds: bool,
    preflight_timeout_sec: float,
    upgrade_generated_seeds: int,
    drop_nonviable_seeds: bool,
) -> list[TargetPlan]:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    plans: list[TargetPlan] = []
    for target in data.get("targets", []) or []:
        target_id = str(target["id"])
        if target_ids and target_id not in target_ids:
            continue
        target_dir = template_run_dir / target_id
        if not target_dir.is_dir():
            print(json.dumps({"event": "skip-missing-template-target", "target_id": target_id}), flush=True)
            continue
        target_out = output_root / target_id
        seed_dir = target_out / "seeds"
        seed_dir.mkdir(parents=True, exist_ok=True)
        selected = select_seed_cases(target_dir, seed_limit=seed_limit, include_crashing=include_crashing)
        first_meta = first_case_meta(target_dir, selected)
        ppd_path = target_out / "fixed.ppd"
        write_fixed_ppd(ppd_path, first_meta, target)
        job_options = str(first_meta.get("job_options") or default_job_options(target))
        seed_count, fallback_seed = export_documents(seed_dir, selected, target)
        if seed_count == 0:
            seed_count, fallback_seed = write_fallback_seed(seed_dir, target)
        if upgrade_generated_seeds > 0:
            generated = generate_upgraded_seeds(
                root=root,
                seed_dir=seed_dir,
                target=target,
                count=upgrade_generated_seeds,
            )
            seed_count += generated
        dictionary = dictionary_for_target(root, target)
        plan = TargetPlan(
            target_id=target_id,
            filter_binary=Path(str(target["filter_binary"])),
            input_mime=str(target.get("input_mime", "")),
            document_kind=str(target.get("document_kind", "")),
            ppd_path=ppd_path,
            job_options=job_options,
            seed_dir=seed_dir,
            out_dir=target_out / "out",
            log_path=target_out / "afl-run.log",
            metrics_path=target_out / "standard-metrics.json",
            dictionary=dictionary,
            seed_count=seed_count,
            fallback_seed=fallback_seed,
        )
        if preflight_seeds:
            plan.seed_count = ensure_viable_seed(
                plan,
                target,
                ld_library_path=ld_library_path,
                timeout_sec=preflight_timeout_sec,
                drop_nonviable=drop_nonviable_seeds,
            )
        plans.append(plan)
    return plans


def select_seed_cases(target_dir: Path, *, seed_limit: int, include_crashing: bool) -> list[Path]:
    cases = sorted(p for p in target_dir.iterdir() if p.is_dir() and p.name.startswith("case-"))
    selected: list[Path] = []
    fallback: list[Path] = []
    for case_dir in cases:
        doc = find_document(case_dir)
        if doc is None:
            continue
        meta = read_json(case_dir / "meta.json")
        crashed = bool(meta.get("crashed"))
        timed_out = bool(meta.get("timed_out"))
        if not crashed and not timed_out:
            selected.append(case_dir)
        elif include_crashing:
            fallback.append(case_dir)
        if seed_limit and len(selected) >= seed_limit:
            break
    if selected:
        return selected[:seed_limit] if seed_limit else selected
    if fallback:
        return fallback[:seed_limit] if seed_limit else fallback
    return []


def first_case_meta(target_dir: Path, selected: list[Path]) -> dict[str, Any]:
    candidates = selected or sorted(p for p in target_dir.iterdir() if p.is_dir() and p.name.startswith("case-"))
    for case_dir in candidates:
        meta = read_json(case_dir / "meta.json")
        if meta:
            return meta
    return {}


def write_fixed_ppd(ppd_path: Path, meta: dict[str, Any], target: dict[str, Any]) -> None:
    ppd_source = meta.get("ppd_path")
    if ppd_source and Path(str(ppd_source)).exists():
        shutil.copy2(str(ppd_source), ppd_path)
        return
    candidate = meta.get("env_overrides", {}).get("PPD") if isinstance(meta.get("env_overrides"), dict) else ""
    if candidate and Path(str(candidate)).exists():
        shutil.copy2(str(candidate), ppd_path)
        return
    ppd_path.write_text(minimal_ppd(str(target.get("id", "smt-afl"))), encoding="utf-8")


def export_documents(seed_dir: Path, selected: list[Path], target: dict[str, Any]) -> tuple[int, bool]:
    count = 0
    for case_dir in selected:
        doc = find_document(case_dir)
        if doc is None:
            continue
        suffix = doc.suffix or default_extension(target)
        out = seed_dir / f"seed-{count:06d}{suffix}"
        shutil.copy2(doc, out)
        count += 1
    return count, False


def write_fallback_seed(seed_dir: Path, target: dict[str, Any]) -> tuple[int, bool]:
    ext = default_extension(target)
    path = seed_dir / f"fallback-000000{ext}"
    kind = str(target.get("document_kind", ""))
    input_mime = str(target.get("input_mime", ""))
    if "pdf" in kind or input_mime == "application/pdf":
        data = b"%PDF-1.1\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    elif "postscript" in kind or "postscript" in input_mime:
        data = b"%!PS\nshowpage\n"
    elif "image" in kind or input_mime.startswith("image/"):
        data = b"P3\n1 1\n255\n0 0 0\n"
    elif "text" in kind or input_mime == "text/plain":
        data = b"hello\n"
    elif "command" in kind or "cups-command" in input_mime:
        data = b"#CUPS-COMMAND\n"
    else:
        data = b"x\n"
    path.write_bytes(data)
    return 1, True


def configure_template_upgrade_env(args: argparse.Namespace) -> None:
    if args.upgrade_generated_seeds <= 0:
        return
    os.environ.setdefault("SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL", str(args.template_expansion_level))
    os.environ.setdefault("SMT_FUZZER_IMAGE_EXPANSION_LEVEL", str(args.template_expansion_level))
    os.environ.setdefault("SMT_FUZZER_TEMPLATE_CYCLE_EPOCHS", str(args.template_cycle_epochs))
    os.environ.setdefault("SMT_FUZZER_IMAGE_CYCLE_EPOCHS", str(args.template_cycle_epochs))
    os.environ.setdefault("SMT_FUZZER_IMAGE_VALID_BIAS", "1")
    os.environ.setdefault("SMT_FUZZER_STRUCTURE_MUTATOR", "1")


def generate_upgraded_seeds(*, root: Path, seed_dir: Path, target: dict[str, Any], count: int) -> int:
    if count <= 0:
        return 0
    _ensure_src_path(root)
    from parser_fuzzers.runner.document_harness import make_document

    target_id = str(target["id"])
    kinds = upgraded_document_kinds(str(target.get("document_kind", "")))
    if not kinds:
        return 0

    existing_hashes = {
        hashlib.sha256(path.read_bytes()).hexdigest()
        for path in seed_dir.iterdir()
        if path.is_file() and path.stat().st_size > 0
    }
    written = 0
    attempts = 0
    max_attempts = max(count * 12, count + 64)
    manifest: list[dict[str, Any]] = []
    while written < count and attempts < max_attempts:
        kind = kinds[attempts % len(kinds)]
        case_index = attempts // len(kinds) + (attempts % len(kinds)) * 100000
        try:
            document = make_document(kind, case_index, target_id=target_id)
        except Exception as exc:  # pragma: no cover - a broken template should not stop the whole campaign
            manifest.append({"kind": kind, "case_index": case_index, "error": f"{type(exc).__name__}: {exc}"})
            attempts += 1
            continue
        digest = hashlib.sha256(document.data).hexdigest()
        if digest in existing_hashes:
            attempts += 1
            continue
        existing_hashes.add(digest)
        suffix = document.extension or default_extension(target)
        out = seed_dir / f"upgrade-{written:06d}-{_safe_name(kind)}{suffix}"
        out.write_bytes(document.data)
        manifest.append(
            {
                "path": str(out),
                "kind": kind,
                "case_index": case_index,
                "description": document.description,
                "mime": document.mime,
                "size": len(document.data),
                "sha256": digest,
            }
        )
        written += 1
        attempts += 1
    (seed_dir.parent / "upgrade-seeds.json").write_text(
        json.dumps(
            {
                "target_id": target_id,
                "requested": count,
                "generated": written,
                "document_kinds": kinds,
                "manifest": manifest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return written


def upgraded_document_kinds(document_kind: str) -> list[str]:
    if document_kind == "cups_raster_feedback_sweep":
        return [
            "cups_raster_feedback_sweep",
            "cups_raster_structural_sweep",
            "cups_raster_coverage_sweep",
            "cups_raster_general_sweep",
        ]
    if document_kind == "cups_raster_coverage_sweep":
        return ["cups_raster_structural_sweep", "cups_raster_coverage_sweep", "cups_raster_general_sweep"]
    if document_kind == "pwg_raster_feedback_sweep":
        return [
            "pwg_raster_feedback_sweep",
            "pwg_raster_structural_sweep",
            "pwg_raster_coverage_sweep",
            "pwg_raster_general_sweep",
        ]
    if document_kind == "pwg_raster_coverage_sweep":
        return ["pwg_raster_structural_sweep", "pwg_raster_coverage_sweep", "pwg_raster_general_sweep"]
    if document_kind == "image_coverage_sweep":
        return ["image_feedback_sweep", "image_coverage_sweep"]
    if document_kind == "pdf_coverage_sweep":
        return ["pdf_semantic_sweep", "pdf_coverage_sweep"]
    if document_kind == "postscript_coverage_sweep":
        return ["postscript_semantic_sweep", "postscript_coverage_sweep"]
    if document_kind == "text_coverage_sweep":
        return ["text_semantic_sweep", "text_coverage_sweep"]
    if document_kind == "command_coverage_sweep":
        return ["command_semantic_sweep", "command_coverage_sweep"]
    return [document_kind] if document_kind else []


def _ensure_src_path(root: Path) -> None:
    src = root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value)[:64]


def ensure_viable_seed(
    plan: TargetPlan,
    target: dict[str, Any],
    *,
    ld_library_path: str,
    timeout_sec: float,
    drop_nonviable: bool = False,
) -> int:
    seeds = sorted(path for path in plan.seed_dir.iterdir() if path.is_file() and path.stat().st_size > 0)
    report: list[dict[str, Any]] = []
    viable = [path for path in seeds if seed_is_viable(plan, path, ld_library_path=ld_library_path, timeout_sec=timeout_sec, report=report)]
    if not viable:
        for index, data in enumerate(fallback_seed_candidates(target)):
            ext = default_extension(target)
            candidate = plan.seed_dir / f"viable-fallback-{index:06d}{ext}"
            candidate.write_bytes(data)
            if seed_is_viable(plan, candidate, ld_library_path=ld_library_path, timeout_sec=timeout_sec, report=report):
                viable.append(candidate)
                break
            try:
                candidate.unlink()
            except OSError:
                pass
    if viable:
        viable_names = {path.name for path in viable}
        for path in seeds:
            if path.name not in viable_names and (drop_nonviable or path.name.startswith("fallback-")):
                try:
                    path.unlink()
                except OSError:
                    pass
        count = len([path for path in plan.seed_dir.iterdir() if path.is_file() and path.stat().st_size > 0])
    else:
        count = len(seeds)
    (plan.seed_dir.parent / "seed-preflight.json").write_text(
        json.dumps(
            {
                "target_id": plan.target_id,
                "viable_seed_count": len(viable),
                "seed_count_after_preflight": count,
                "checked": report,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return count


def seed_is_viable(
    plan: TargetPlan,
    seed: Path,
    *,
    ld_library_path: str,
    timeout_sec: float,
    report: list[dict[str, Any]],
) -> bool:
    if not plan.filter_binary.exists():
        report.append({"seed": str(seed), "status": "missing-binary"})
        return False
    env = direct_filter_env(plan, ld_library_path)
    cmd = [str(plan.filter_binary), "1", "afl", "afl", "1", plan.job_options, str(seed)]
    started = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        report.append({"seed": str(seed), "status": "timeout", "timeout_sec": timeout_sec})
        return False
    stderr = result.stderr.decode("utf-8", errors="replace")
    crashed = result.returncode < 0 or result.returncode == 86 or "ERROR: AddressSanitizer" in stderr
    status = "crash" if crashed else "ok"
    report.append(
        {
            "seed": str(seed),
            "status": status,
            "returncode": result.returncode,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    )
    return not crashed


def direct_filter_env(plan: TargetPlan, ld_library_path: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ASAN_OPTIONS": env.get("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86"),
            "PPD": str(plan.ppd_path),
            "CONTENT_TYPE": plan.input_mime or "application/octet-stream",
            "FINAL_CONTENT_TYPE": "application/octet-stream",
            "PRINTER": "parser-fuzzers",
            "DEVICE_URI": "file:/dev/null",
            "SMT_FUZZER_TARGET_ID": plan.target_id,
        }
    )
    if ld_library_path:
        env["LD_LIBRARY_PATH"] = ld_library_path + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    return env


def fallback_seed_candidates(target: dict[str, Any]) -> list[bytes]:
    kind = str(target.get("document_kind", ""))
    input_mime = str(target.get("input_mime", ""))
    if "pdf" in kind or input_mime == "application/pdf":
        return [
            b"x\n",
            b"%PDF-1.1\n%%EOF\n",
            b"%PDF-1.1\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
        ]
    if "postscript" in kind or "postscript" in input_mime:
        return [b"x\n", b"%!PS\nshowpage\n", b"%!PS-Adobe-3.0\n%%Pages: 1\nshowpage\n%%EOF\n"]
    if "image" in kind or input_mime.startswith("image/"):
        return [b"x\n", b"P1\n1 1\n0\n", b"P3\n1 1\n255\n0 0 0\n", minimal_png()]
    if "text" in kind or input_mime == "text/plain":
        return [b"x\n", b"hello\n"]
    if "command" in kind or "cups-command" in input_mime:
        return [b"x\n", b"#CUPS-COMMAND\n"]
    return [b"x\n"]


def minimal_png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", checksum)

    raw_scanline = b"\x00\x00\x00\x00"
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw_scanline))
        + chunk(b"IEND", b"")
    )


def find_document(case_dir: Path) -> Path | None:
    for path in sorted(case_dir.glob("document.*")):
        if path.is_file() and path.stat().st_size > 0:
            return path
    return None


def dictionary_for_target(root: Path, target: dict[str, Any]) -> Path | None:
    kind = str(target.get("document_kind", ""))
    input_mime = str(target.get("input_mime", ""))
    if "raster" in kind or input_mime in {"application/vnd.cups-pwg", "application/vnd.cups-raster"}:
        path = root / RASTER_DICT
        return path if path.exists() else None
    return None


def default_extension(target: dict[str, Any]) -> str:
    kind = str(target.get("document_kind", ""))
    input_mime = str(target.get("input_mime", ""))
    if "pwg" in kind or input_mime == "application/vnd.cups-pwg":
        return ".pwg"
    if "cups_raster" in kind or input_mime == "application/vnd.cups-raster":
        return ".ras"
    if "pdf" in kind or input_mime == "application/pdf":
        return ".pdf"
    if "postscript" in kind or input_mime == "application/postscript":
        return ".ps"
    if "image" in kind:
        return ".ppm"
    if "text" in kind or input_mime == "text/plain":
        return ".txt"
    if "command" in kind:
        return ".cmd"
    return ".bin"


def default_job_options(target: dict[str, Any]) -> str:
    kind = str(target.get("document_kind", ""))
    options = ["PageSize=Letter", "PageRegion=Letter", "ColorModel=Gray", "PrintQuality=Normal", "MediaType=Plain"]
    if "raster" not in kind and "pwg" not in kind:
        options.extend(["Duplex=None", "Resolution=300x300dpi"])
    return " ".join(options)


def minimal_ppd(name: str) -> str:
    return f"""*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "SMTAFL.PPD"
*Manufacturer: "parser-fuzzers"
*Product: "({name})"
*ModelName: "{name}"
*NickName: "{name}"
*ShortNickName: "{name}"
*ColorDevice: True
*DefaultPageSize: Letter
*PageSize Letter/Letter: "<</PageSize[612 792]>>setpagedevice"
*DefaultPageRegion: Letter
*PageRegion Letter/Letter: "<</PageSize[612 792]>>setpagedevice"
*DefaultImageableArea: Letter
*ImageableArea Letter/Letter: "0 0 612 792"
*DefaultPaperDimension: Letter
*PaperDimension Letter/Letter: "612 792"
*DefaultColorModel: Gray
*ColorModel Gray/Gray: "<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice"
*ColorModel RGB/RGB: "<</cupsColorSpace 1/cupsBitsPerColor 8/cupsBitsPerPixel 24>>setpagedevice"
*DefaultResolution: 300dpi
*Resolution 300dpi/300 DPI: "<</HWResolution[300 300]>>setpagedevice"
*cupsFilter2: "application/octet-stream application/octet-stream 0 -"
*% EOF
"""


def run_scheduler(
    *,
    plans: list[TargetPlan],
    args: argparse.Namespace,
    ld_library_path: str,
    output_root: Path,
) -> int:
    active: dict[str, subprocess.Popen[bytes]] = {}
    pending = list(plans)
    completed: dict[str, int] = {}
    last_monitor = 0.0
    stop_reason = "complete"
    while pending or active:
        now = time.monotonic()
        while pending and len(active) < max(1, args.max_parallel):
            plan = pending.pop(0)
            status = launch_target(plan, args, ld_library_path)
            if status is None:
                completed[plan.target_id] = 2
            else:
                active[plan.target_id] = status
        for target_id, proc in list(active.items()):
            status = proc.poll()
            if status is not None:
                completed[target_id] = status
                active.pop(target_id)
                plan = next(item for item in plans if item.target_id == target_id)
                write_metrics(plan)
        if now - last_monitor >= args.monitor_interval_sec:
            last_monitor = now
            snapshot = {
                "event": "monitor",
                "active": sorted(active),
                "pending": len(pending),
                "completed": len(completed),
                "campaign_gb": round(path_bytes(output_root) / (1024.0**3), 3),
                "free_gb": free_gb(Path("/data")),
            }
            print(json.dumps(snapshot, sort_keys=True), flush=True)
            if snapshot["free_gb"] < args.min_free_gb:
                stop_reason = "disk-free-low"
                terminate_all(active)
                pending.clear()
            elif snapshot["campaign_gb"] > args.max_campaign_gb:
                stop_reason = "campaign-growth-limit"
                terminate_all(active)
                pending.clear()
        time.sleep(1.0)
    for plan in plans:
        if not plan.metrics_path.exists():
            write_metrics(plan)
    summary = {
        "event": "done",
        "stop_reason": stop_reason,
        "targets": len(plans),
        "completed": completed,
        "campaign_gb": round(path_bytes(output_root) / (1024.0**3), 3),
        "free_gb": free_gb(Path("/data")),
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if stop_reason == "complete" else 90


def launch_target(plan: TargetPlan, args: argparse.Namespace, ld_library_path: str) -> subprocess.Popen[bytes] | None:
    plan.out_dir.parent.mkdir(parents=True, exist_ok=True)
    if not plan.filter_binary.exists():
        print(json.dumps({"event": "skip-missing-binary", "target_id": plan.target_id, "binary": str(plan.filter_binary)}), flush=True)
        return None
    env = os.environ.copy()
    env.update(
        {
            "AFL_NO_UI": "1",
            "AFL_SKIP_CPUFREQ": "1",
            "AFL_CRASH_EXITCODE": "86",
            "AFL_SKIP_CRASHES": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            "ASAN_OPTIONS": env.get("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=0:exitcode=86"),
            "PPD": str(plan.ppd_path),
            "CONTENT_TYPE": plan.input_mime or "application/octet-stream",
            "FINAL_CONTENT_TYPE": "application/octet-stream",
            "PRINTER": "parser-fuzzers",
            "DEVICE_URI": "file:/dev/null",
            "SMT_FUZZER_TARGET_ID": plan.target_id,
        }
    )
    if ld_library_path:
        env["LD_LIBRARY_PATH"] = ld_library_path + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    cmd = [
        args.afl_fuzz,
        "-V",
        str(args.duration_sec),
        "-t",
        str(args.timeout_ms),
        "-m",
        "none",
        "-i",
        str(plan.seed_dir),
        "-o",
        str(plan.out_dir),
        "-T",
        f"parser-fuzzers-{plan.target_id}",
    ]
    if plan.dictionary:
        cmd.extend(["-x", str(plan.dictionary)])
    cmd.extend(["--", str(plan.filter_binary), "1", "afl", "afl", "1", plan.job_options, "@@"])
    plan_json = plan.out_dir.parent / "run-command.json"
    plan_json.write_text(
        json.dumps({"argv": cmd, "env": selected_env(env), **plan_to_json(plan)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    log = plan.log_path.open("wb")
    print(json.dumps({"event": "launch", "target_id": plan.target_id, "seed_count": plan.seed_count, "fallback_seed": plan.fallback_seed}), flush=True)
    return subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)


def write_metrics(plan: TargetPlan) -> None:
    payload = {
        "schema_version": "template-multi-afl-target-v1",
        "target_id": plan.target_id,
        "seed_count": plan.seed_count,
        "fallback_seed": plan.fallback_seed,
        "dictionary": str(plan.dictionary) if plan.dictionary else "",
        "afl": read_afl_stats(plan.out_dir),
        "paths": {
            "seed_dir": str(plan.seed_dir),
            "out_dir": str(plan.out_dir),
            "ppd": str(plan.ppd_path),
            "log": str(plan.log_path),
        },
    }
    plan.metrics_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_afl_stats(out_dir: Path) -> dict[str, Any]:
    stats_path = find_fuzzer_stats(out_dir)
    if not stats_path:
        return {"status": "missing-fuzzer-stats", "out_dir": str(out_dir)}
    stats: dict[str, Any] = {"status": "ok", "fuzzer_stats": str(stats_path)}
    for line in stats_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    for key in ("run_time", "execs_done", "corpus_count", "corpus_found", "saved_crashes", "saved_hangs"):
        try:
            stats[key] = int(str(stats.get(key, "0")))
        except ValueError:
            pass
    try:
        stats["execs_per_sec"] = float(str(stats.get("execs_per_sec", "0")))
    except ValueError:
        pass
    return stats


def find_fuzzer_stats(out_dir: Path) -> Path | None:
    candidates = [out_dir / "default" / "fuzzer_stats", out_dir / "fuzzer_stats"]
    candidates.extend(sorted(out_dir.glob("*/fuzzer_stats")))
    for path in candidates:
        if path.exists():
            return path
    return None


def terminate_all(active: dict[str, subprocess.Popen[bytes]]) -> None:
    for proc in active.values():
        try:
            proc.terminate()
        except ProcessLookupError:
            pass


def local_filter_library_path(root: Path) -> str:
    pieces = [
        root / "work" / "afl-install" / "libcupsfilters" / "lib",
        root / "work" / "afl-install" / "libppd" / "lib",
        Path("/data/pre-gsoc/env/pdfio-install/lib"),
    ]
    return ":".join(str(path) for path in pieces if path.exists())


def path_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def free_gb(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return round(usage.free / (1024.0**3), 3)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def selected_env(env: dict[str, str]) -> dict[str, str]:
    keys = [
        "AFL_NO_UI",
        "AFL_SKIP_CPUFREQ",
        "AFL_CRASH_EXITCODE",
        "AFL_SKIP_CRASHES",
        "ASAN_OPTIONS",
        "PPD",
        "CONTENT_TYPE",
        "FINAL_CONTENT_TYPE",
        "LD_LIBRARY_PATH",
        "SMT_FUZZER_TARGET_ID",
    ]
    return {key: env[key] for key in keys if key in env}


def plan_to_json(plan: TargetPlan) -> dict[str, Any]:
    return {
        "target_id": plan.target_id,
        "filter_binary": str(plan.filter_binary),
        "input_mime": plan.input_mime,
        "document_kind": plan.document_kind,
        "ppd_path": str(plan.ppd_path),
        "job_options": plan.job_options,
        "seed_dir": str(plan.seed_dir),
        "out_dir": str(plan.out_dir),
        "log_path": str(plan.log_path),
        "metrics_path": str(plan.metrics_path),
        "dictionary": str(plan.dictionary) if plan.dictionary else "",
        "seed_count": plan.seed_count,
        "fallback_seed": plan.fallback_seed,
    }


if __name__ == "__main__":
    raise SystemExit(main())
