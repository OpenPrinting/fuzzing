from __future__ import annotations

import argparse
import json
from pathlib import Path

from parser_fuzzers.afl import afl_build_env, build_afl_plan, print_afl_plan, run_afl_plan
from parser_fuzzers.afl_integration.seed_export import export_template_seeds
from parser_fuzzers.afl_integration.template_seed_generation import generate_template_seeds
from parser_fuzzers.arithmetic_explorer import run_arithmetic_explore
from parser_fuzzers.auto_expand import build_auto_expand_plan, write_auto_expand_plan
from parser_fuzzers.baseline_compare import inspect_oss_fuzz_cups_filters, run_local_baseline_comparison
from parser_fuzzers.crash_dedup import dedup_run
from parser_fuzzers.dynamic_constraints import build_dynamic_compare_profile, write_dynamic_compare_profile
from parser_fuzzers.experiment import estimate_cpu_hours, load_experiment_rows
from parser_fuzzers.hashing import sha256_file
from parser_fuzzers.loop_metrics import write_standard_loop_metrics
from parser_fuzzers.models import BranchEvent
from parser_fuzzers.multitarget_runner import run_multitarget_monitor
from parser_fuzzers.output_feedback import build_output_feedback_profile, write_output_feedback_profile
from parser_fuzzers.patcher import apply_solver_result, load_solver_result, write_solver_result
from parser_fuzzers.run_recovery import recover_run_summary
from parser_fuzzers.run_metrics import summarize_run_metrics, write_run_metrics
from parser_fuzzers.run_set_metrics import render_run_set_markdown, summarize_run_set, write_run_set_metrics
from parser_fuzzers.source_constraints import mine_source_constraints, write_source_constraint_profile
from parser_fuzzers.solver import MissingSolverError, condition_holds, read_event_value, solve_event
from parser_fuzzers.template_feedback import build_feedback_profile, write_feedback_profile
from parser_fuzzers.validation import validate_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="parser-fuzzers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate bug metadata and configs")
    validate_parser.add_argument("--bugs", default="bugs")
    validate_parser.add_argument("--configs", default="configs")
    validate_parser.add_argument(
        "--allow-missing-local-artifacts",
        action="store_true",
        help=(
            "demote missing private reproducer/report paths to warnings; useful for clone-only smoke runs "
            "outside the original /data/pre-gsoc workspace"
        ),
    )

    solve_parser = subparsers.add_parser("solve-event", help="solve one branch event and emit patches")
    solve_parser.add_argument("--event", required=True)
    solve_parser.add_argument("--input")
    solve_parser.add_argument("--output")
    solve_parser.add_argument("--allow-fallback", action="store_true")

    patch_parser = subparsers.add_parser("patch-input", help="apply solver patches to an input")
    patch_parser.add_argument("--result", required=True)
    patch_parser.add_argument("--input")
    patch_parser.add_argument("--output-dir", default="work/corpus/smt")

    smoke_parser = subparsers.add_parser("smoke", help="run a synthetic solver-to-patch workflow")
    smoke_parser.add_argument("--work-dir", default="work/smoke")
    smoke_parser.add_argument("--strict-z3", action="store_true")

    plan_parser = subparsers.add_parser("plan-experiment", help="print experiment matrix and cost")
    plan_parser.add_argument("--configs", default="configs")
    plan_parser.add_argument("--targets", type=int, default=3)
    plan_parser.add_argument("--trials", type=int, default=10)
    plan_parser.add_argument("--hours", type=int, default=24)

    afl_prepare_parser = subparsers.add_parser("afl-prepare", help="prepare AFL++ corpus/dict and print command")
    _add_afl_common_args(afl_prepare_parser)
    afl_prepare_parser.add_argument("--json", action="store_true")

    afl_run_parser = subparsers.add_parser("afl-run", help="print or execute an AFL++ run")
    _add_afl_common_args(afl_run_parser)
    afl_run_parser.add_argument("--execute", action="store_true", help="actually launch afl-fuzz")
    afl_run_parser.add_argument("--json", action="store_true", help="print JSON when not executing")
    afl_run_parser.add_argument(
        "--allow-non-instrumented",
        action="store_true",
        help="allow executing a non-AFL-instrumented binary; standard runs should not use this",
    )

    afl_env_parser = subparsers.add_parser("afl-build-env", help="print AFL++ compiler environment")
    afl_env_parser.add_argument("--configs", default="configs")
    afl_env_parser.add_argument("--json", action="store_true")

    multitarget_parser = subparsers.add_parser(
        "multitarget-monitor",
        help="run multi-target PPD+document monitoring harness",
    )
    multitarget_parser.add_argument("--config", default="configs/parser_targets.yaml")
    multitarget_parser.add_argument("--work-root", default="work/multitarget")
    multitarget_parser.add_argument(
        "--filter-root",
        help="rewrite direct_filter filter_binary entries to this directory before running",
    )
    multitarget_parser.add_argument("--workers", type=int, default=4)
    multitarget_parser.add_argument("--cases-per-target", type=int)
    multitarget_parser.add_argument("--duration-sec", type=int)
    multitarget_parser.add_argument("--timeout-sec", type=int, default=15)
    multitarget_parser.add_argument("--max-run-gb", type=float, default=0.0)
    multitarget_parser.add_argument("--discard-stdout", action="store_true")
    multitarget_parser.add_argument("--discovery-mode", choices=["crash", "coverage"], default="crash")
    multitarget_parser.add_argument("--scheduler", choices=["round-robin", "novelty"], default="round-robin")
    multitarget_parser.add_argument(
        "--min-target-share",
        type=float,
        default=0.0,
        help="minimum scheduled-attempt share per target during duration campaigns",
    )
    multitarget_parser.add_argument(
        "--max-target-share",
        type=float,
        default=1.0,
        help="maximum scheduled-attempt share per target during duration campaigns; 0 disables the cap",
    )
    multitarget_parser.add_argument("--runtime-skip", action="store_true")
    multitarget_parser.add_argument("--crash-skip-after", type=int, default=1)
    multitarget_parser.add_argument(
        "--seed-skip-state",
        help="preload runtime crash-shape suppression from a previous discovery_state.json",
    )
    multitarget_parser.add_argument(
        "--auto-skip-state",
        action="store_true",
        help="preload the newest useful discovery_state.json under --auto-skip-root when --seed-skip-state is absent",
    )
    multitarget_parser.add_argument(
        "--auto-skip-root",
        default="work",
        help="bounded search root for --auto-skip-state",
    )
    multitarget_parser.add_argument(
        "--generalized-skip",
        action="store_true",
        help="also suppress whole target/PPD/document families after repeated seeded/runtime crash shapes",
    )
    multitarget_parser.add_argument("--family-skip-after", type=int, default=32)
    multitarget_parser.add_argument(
        "--skip-probe-rate",
        type=float,
        default=0.0,
        help="deterministic fraction of runtime-suppressed cases to still execute",
    )
    multitarget_parser.add_argument(
        "--skip-only-stop-after",
        type=int,
        default=0,
        help="stop a duration campaign after this many consecutive skipped cases without a submitted run; 0 disables",
    )
    multitarget_parser.add_argument(
        "--stagnation-stop-after-sec",
        type=int,
        default=0,
        help="stop coverage campaigns after this many seconds without retained coverage or a new crash; 0 disables",
    )
    multitarget_parser.add_argument(
        "--summary-mode",
        choices=["full", "concise"],
        default="full",
        help="write full per-result summary.json or concise metadata-only summary.json",
    )
    multitarget_parser.add_argument("--prune-uninteresting", action="store_true")

    arithmetic_parser = subparsers.add_parser(
        "arithmetic-explore",
        help="run time-budgeted cross-input arithmetic boundary exploration",
    )
    arithmetic_parser.add_argument("--work-dir", default="work/arithmetic-explore")
    arithmetic_parser.add_argument("--duration-sec", type=int, default=600)
    arithmetic_parser.add_argument("--workers", type=int, default=4)
    arithmetic_parser.add_argument("--timeout-sec", type=int, default=5)
    arithmetic_parser.add_argument("--filter-binary", default="/usr/lib/cups/filter/pwgtoraster")

    dedup_parser = subparsers.add_parser("dedup-crashes", help="deduplicate crashes from a run directory")
    dedup_parser.add_argument("--run-dir", required=True)
    dedup_parser.add_argument("--output-json")
    dedup_parser.add_argument("--output-md")
    dedup_parser.add_argument("--include-timeouts", action="store_true")
    dedup_parser.add_argument("--keep-infra", action="store_true")

    feedback_parser = subparsers.add_parser(
        "build-template-feedback",
        help="build a structural template feedback profile from retained/crashing run cases",
    )
    feedback_parser.add_argument("--run-dir", required=True)
    feedback_parser.add_argument("--output", required=True)
    feedback_parser.add_argument("--max-cases-per-kind", type=int, default=128)

    output_feedback_parser = subparsers.add_parser(
        "build-output-feedback",
        help="build an output-structure feedback profile from run timeline semantic shapes",
    )
    output_feedback_parser.add_argument("--run-dir", required=True)
    output_feedback_parser.add_argument("--output", required=True)

    export_seeds_parser = subparsers.add_parser(
        "export-template-seeds",
        help="export retained template-generated documents into an AFL++ seed directory",
    )
    export_seeds_parser.add_argument("--run-dir", required=True)
    export_seeds_parser.add_argument("--output-dir", required=True)
    export_seeds_parser.add_argument("--target-id", action="append", default=[])
    export_seeds_parser.add_argument("--extension", action="append", default=[])
    export_seeds_parser.add_argument("--limit", type=int, default=0)
    export_seeds_parser.add_argument("--include-crashes", action="store_true")
    export_seeds_parser.add_argument("--include-ppd", action="store_true")

    generate_seeds_parser = subparsers.add_parser(
        "generate-template-seeds",
        help="generate structured template documents directly into an AFL++ seed directory",
    )
    generate_seeds_parser.add_argument("--document-kind", required=True)
    generate_seeds_parser.add_argument("--output-dir", required=True)
    generate_seeds_parser.add_argument("--count", type=int, default=64)
    generate_seeds_parser.add_argument("--target-id", default="")
    generate_seeds_parser.add_argument("--start-index", type=int, default=0)
    generate_seeds_parser.add_argument("--extension", action="append", default=[])

    recover_parser = subparsers.add_parser(
        "recover-run-summary",
        help="recover concise run summaries from timeline.jsonl when a campaign did not finish cleanly",
    )
    recover_parser.add_argument("--run-dir", required=True)

    metrics_parser = subparsers.add_parser(
        "summarize-run-metrics",
        help="summarize run, dedup, AFL++, and optional LLVM coverage metrics as JSON",
    )
    metrics_parser.add_argument("--run-dir", required=True)
    metrics_parser.add_argument("--afl-output-dir")
    metrics_parser.add_argument("--llvm-coverage-json")
    metrics_parser.add_argument("--output")

    loop_metrics_parser = subparsers.add_parser(
        "summarize-loop-metrics",
        help="summarize a template -> AFL++ -> feedback-template campaign as JSON",
    )
    loop_metrics_parser.add_argument("--campaign-dir", required=True)
    loop_metrics_parser.add_argument("--output")

    run_set_metrics_parser = subparsers.add_parser(
        "summarize-run-set",
        help="summarize multiple campaign directories into aggregate metrics",
    )
    run_set_metrics_parser.add_argument("--root", action="append", required=True)
    run_set_metrics_parser.add_argument("--output", required=True)
    run_set_metrics_parser.add_argument("--output-md")

    oss_status_parser = subparsers.add_parser(
        "oss-fuzz-status",
        help="inspect local OSS-Fuzz cups-filters availability",
    )
    oss_status_parser.add_argument("--oss-fuzz-dir", default="/data/pre-gsoc/oss-fuzz")

    compare_parser = subparsers.add_parser(
        "compare-baseline-metrics",
        help="run a local OSS-Fuzz-style baseline and an optimized semantic run, then compare metrics",
    )
    compare_parser.add_argument("--config", default="work/parser_targets_cold_semantic_llvm.yaml")
    compare_parser.add_argument("--work-root", default="work/baseline-comparison")
    compare_parser.add_argument("--oss-fuzz-dir", default="/data/pre-gsoc/oss-fuzz")
    compare_parser.add_argument("--duration-sec", type=int, default=60)
    compare_parser.add_argument("--workers", type=int, default=4)
    compare_parser.add_argument("--timeout-sec", type=int, default=5)
    compare_parser.add_argument("--max-run-gb", type=float, default=10.0)
    compare_parser.add_argument("--enable-llvm-profiles", action="store_true")
    compare_parser.add_argument("--export-llvm-coverage", action="store_true")
    compare_parser.add_argument(
        "--optimized-policy",
        choices=["avoidance", "no-crash-avoidance"],
        default="avoidance",
        help="choose whether the optimized comparison run uses crash-avoidance suppression",
    )

    auto_expand_parser = subparsers.add_parser(
        "auto-expand",
        help="build a frontier feedback profile and next-run expansion plan from previous campaigns",
    )
    auto_expand_parser.add_argument("--search-root", default="work")
    auto_expand_parser.add_argument("--output-profile", default="work/template-feedback/auto-expand-feedback.json")
    auto_expand_parser.add_argument("--plan-output", default="")
    auto_expand_parser.add_argument("--max-runs", type=int, default=8)
    auto_expand_parser.add_argument("--max-cases-per-kind", type=int, default=160)
    auto_expand_parser.add_argument("--stale-window", type=int, default=5000)
    auto_expand_parser.add_argument("--duration-sec", type=int, default=1200)
    auto_expand_parser.add_argument("--workers", type=int, default=10)
    auto_expand_parser.add_argument("--timeout-sec", type=int, default=5)
    auto_expand_parser.add_argument("--max-run-gb", type=float, default=10.0)
    auto_expand_parser.add_argument("--skip-probe-rate", type=float, default=0.01)

    source_constraints_parser = subparsers.add_parser(
        "mine-source-constraints",
        help="mine source-code comparison and field hints for SMT/template biasing",
    )
    source_constraints_parser.add_argument(
        "--source-dir",
        action="append",
        required=True,
        help="C/C++ source directory or file to scan; can be repeated",
    )
    source_constraints_parser.add_argument("--output", required=True)
    source_constraints_parser.add_argument("--max-records", type=int, default=2000)

    dynamic_constraints_parser = subparsers.add_parser(
        "summarize-dynamic-constraints",
        help="summarize per-case dynamic compare traces from a run directory",
    )
    dynamic_constraints_parser.add_argument("--run-dir", required=True)
    dynamic_constraints_parser.add_argument("--output", required=True)
    dynamic_constraints_parser.add_argument("--max-records", type=int, default=2000)

    args = parser.parse_args(argv)
    if args.command == "validate":
        return _cmd_validate(args)
    if args.command == "solve-event":
        return _cmd_solve_event(args)
    if args.command == "patch-input":
        return _cmd_patch_input(args)
    if args.command == "smoke":
        return _cmd_smoke(args)
    if args.command == "plan-experiment":
        return _cmd_plan_experiment(args)
    if args.command == "afl-prepare":
        return _cmd_afl_prepare(args)
    if args.command == "afl-run":
        return _cmd_afl_run(args)
    if args.command == "afl-build-env":
        return _cmd_afl_build_env(args)
    if args.command == "multitarget-monitor":
        return _cmd_multitarget_monitor(args)
    if args.command == "arithmetic-explore":
        return _cmd_arithmetic_explore(args)
    if args.command == "dedup-crashes":
        return _cmd_dedup_crashes(args)
    if args.command == "build-template-feedback":
        return _cmd_build_template_feedback(args)
    if args.command == "build-output-feedback":
        return _cmd_build_output_feedback(args)
    if args.command == "export-template-seeds":
        return _cmd_export_template_seeds(args)
    if args.command == "generate-template-seeds":
        return _cmd_generate_template_seeds(args)
    if args.command == "recover-run-summary":
        return _cmd_recover_run_summary(args)
    if args.command == "summarize-run-metrics":
        return _cmd_summarize_run_metrics(args)
    if args.command == "summarize-loop-metrics":
        return _cmd_summarize_loop_metrics(args)
    if args.command == "summarize-run-set":
        return _cmd_summarize_run_set(args)
    if args.command == "oss-fuzz-status":
        return _cmd_oss_fuzz_status(args)
    if args.command == "compare-baseline-metrics":
        return _cmd_compare_baseline_metrics(args)
    if args.command == "auto-expand":
        return _cmd_auto_expand(args)
    if args.command == "mine-source-constraints":
        return _cmd_mine_source_constraints(args)
    if args.command == "summarize-dynamic-constraints":
        return _cmd_summarize_dynamic_constraints(args)
    parser.error(f"unknown command: {args.command}")
    return 2


def _cmd_validate(args: argparse.Namespace) -> int:
    issues = validate_all(
        args.bugs,
        args.configs,
        require_local_artifacts=not args.allow_missing_local_artifacts,
    )
    for issue in issues:
        print(f"{issue.level.upper()}: {issue.path}: {issue.message}")
    error_count = sum(1 for issue in issues if issue.level == "error")
    warning_count = sum(1 for issue in issues if issue.level == "warning")
    print(json.dumps({"errors": error_count, "warnings": warning_count}, sort_keys=True))
    return 1 if error_count else 0


def _cmd_solve_event(args: argparse.Namespace) -> int:
    event = _load_event(args.event)
    input_path = Path(args.input or event.input_path)
    input_bytes = input_path.read_bytes()
    _verify_hash(event, input_path)
    try:
        result = solve_event(event, input_bytes, allow_fallback=args.allow_fallback)
    except MissingSolverError as exc:
        print(str(exc))
        return 2
    if args.output:
        write_solver_result(result, args.output)
    else:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status in {"sat", "already_satisfied"} else 1


def _cmd_patch_input(args: argparse.Namespace) -> int:
    result = load_solver_result(args.result)
    input_path = Path(args.input or result.event.input_path)
    output = apply_solver_result(result, input_path, args.output_dir)
    print(output)
    return 0


def _cmd_smoke(args: argparse.Namespace) -> int:
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    input_path = work_dir / "input.bin"
    event_path = work_dir / "event.json"
    result_path = work_dir / "result.json"
    output_dir = work_dir / "corpus"

    input_path.write_bytes(b"\x00SMT-FUZZER-SMOKE\n")
    event = BranchEvent(
        target_id="synthetic_eq_u8",
        input_path=str(input_path),
        input_sha256=sha256_file(input_path),
        offset=0,
        width=1,
        endianness="little",
        signed=False,
        op="eq",
        rhs=0x41,
        description="first byte must become ASCII A",
    )
    event_path.write_text(json.dumps(event.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        result = solve_event(event, input_path.read_bytes(), allow_fallback=not args.strict_z3)
    except MissingSolverError as exc:
        print(str(exc))
        return 2
    write_solver_result(result, result_path)
    output_path = apply_solver_result(result, input_path, output_dir)
    patched = output_path.read_bytes()
    patched_value = read_event_value(event, patched)
    ok = condition_holds(event, patched_value)
    print(
        json.dumps(
            {
                "ok": ok,
                "event": str(event_path),
                "result": str(result_path),
                "patched_input": str(output_path),
                "reason": result.reason,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if ok else 1


def _cmd_plan_experiment(args: argparse.Namespace) -> int:
    rows = load_experiment_rows(Path(args.configs) / "experiment.yaml")
    cpu_hours = estimate_cpu_hours(len(rows), args.targets, args.trials, args.hours)
    print("ID  Name                     Dict  CmpLog  Grammar  SMT")
    for row in rows:
        print(
            f"{row.id:<3} {row.name:<24} "
            f"{_yes(row.dictionary):<5} {_yes(row.cmplog):<7} {_yes(row.grammar):<8} {_yes(row.smt):<3}"
        )
    print()
    print(
        json.dumps(
            {
                "configs": len(rows),
                "targets": args.targets,
                "trials": args.trials,
                "hours_per_trial": args.hours,
                "cpu_hours": cpu_hours,
            },
            sort_keys=True,
        )
    )
    return 0


def _cmd_afl_prepare(args: argparse.Namespace) -> int:
    plan = _build_afl_plan_from_args(args)
    print_afl_plan(plan, as_json=args.json)
    return 0


def _cmd_afl_run(args: argparse.Namespace) -> int:
    plan = _build_afl_plan_from_args(args)
    if args.execute:
        return run_afl_plan(plan, execute=True, require_instrumented=not args.allow_non_instrumented)
    print_afl_plan(plan, as_json=args.json)
    return 0


def _cmd_afl_build_env(args: argparse.Namespace) -> int:
    env = afl_build_env(args.configs)
    if args.json:
        print(json.dumps(env, indent=2, sort_keys=True))
    else:
        for key, value in env.items():
            print(f"export {key}={_shell_quote(value)}")
    return 0


def _cmd_multitarget_monitor(args: argparse.Namespace) -> int:
    run_command = (
        "PYTHONPATH=src python3 -m parser_fuzzers.cli multitarget-monitor "
        f"--config {_shell_quote(args.config)} "
        f"--work-root {_shell_quote(args.work_root)} "
        f"--workers {args.workers} "
        f"--timeout-sec {args.timeout_sec}"
    )
    if args.filter_root:
        run_command += f" --filter-root {_shell_quote(args.filter_root)}"
    if args.cases_per_target is not None:
        run_command += f" --cases-per-target {args.cases_per_target}"
    if args.duration_sec is not None:
        run_command += f" --duration-sec {args.duration_sec}"
    if args.max_run_gb:
        run_command += f" --max-run-gb {args.max_run_gb:g}"
    if args.discard_stdout:
        run_command += " --discard-stdout"
    if args.discovery_mode != "crash":
        run_command += f" --discovery-mode {args.discovery_mode}"
    if args.scheduler != "round-robin":
        run_command += f" --scheduler {args.scheduler}"
    if args.min_target_share:
        run_command += f" --min-target-share {args.min_target_share:g}"
    if args.max_target_share != 1.0:
        run_command += f" --max-target-share {args.max_target_share:g}"
    if args.runtime_skip:
        run_command += " --runtime-skip"
    if args.crash_skip_after != 1:
        run_command += f" --crash-skip-after {args.crash_skip_after}"
    if args.seed_skip_state:
        run_command += f" --seed-skip-state {_shell_quote(args.seed_skip_state)}"
    if args.auto_skip_state:
        run_command += " --auto-skip-state"
    if args.auto_skip_root != "work":
        run_command += f" --auto-skip-root {_shell_quote(args.auto_skip_root)}"
    if args.generalized_skip:
        run_command += " --generalized-skip"
    if args.family_skip_after != 32:
        run_command += f" --family-skip-after {args.family_skip_after}"
    if args.skip_probe_rate:
        run_command += f" --skip-probe-rate {args.skip_probe_rate:g}"
    if args.skip_only_stop_after:
        run_command += f" --skip-only-stop-after {args.skip_only_stop_after}"
    if args.stagnation_stop_after_sec:
        run_command += f" --stagnation-stop-after-sec {args.stagnation_stop_after_sec}"
    if args.summary_mode != "full":
        run_command += f" --summary-mode {args.summary_mode}"
    if args.prune_uninteresting:
        run_command += " --prune-uninteresting"
    summary = run_multitarget_monitor(
        config_path=args.config,
        work_root=args.work_root,
        workers=args.workers,
        cases_per_target=args.cases_per_target,
        duration_sec=args.duration_sec,
        timeout_sec=args.timeout_sec,
        max_run_gb=args.max_run_gb or None,
        run_command=run_command,
        capture_stdout=not args.discard_stdout,
        filter_root=args.filter_root,
        discovery_mode=args.discovery_mode,
        scheduler=args.scheduler,
        min_target_share=args.min_target_share,
        max_target_share=args.max_target_share,
        runtime_skip=args.runtime_skip,
        crash_skip_after=args.crash_skip_after,
        prune_uninteresting=args.prune_uninteresting,
        seed_skip_state_path=args.seed_skip_state,
        auto_skip_state=args.auto_skip_state,
        auto_skip_search_root=args.auto_skip_root,
        generalized_skip=args.generalized_skip,
        family_skip_after=args.family_skip_after,
        skip_probe_rate=args.skip_probe_rate,
        skip_only_stop_after=args.skip_only_stop_after,
        stagnation_stop_after_sec=args.stagnation_stop_after_sec,
        summary_mode=args.summary_mode,
    )
    if args.duration_sec is not None:
        print(json.dumps(summary.concise_dict(), indent=2, sort_keys=True))
    else:
        print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_arithmetic_explore(args: argparse.Namespace) -> int:
    summary = run_arithmetic_explore(
        work_dir=args.work_dir,
        duration_sec=args.duration_sec,
        workers=args.workers,
        timeout_sec=args.timeout_sec,
        filter_binary=args.filter_binary,
    )
    print(json.dumps(summary.concise_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_dedup_crashes(args: argparse.Namespace) -> int:
    summary = dedup_run(
        args.run_dir,
        output_json=args.output_json,
        output_md=args.output_md,
        include_timeouts=args.include_timeouts,
        exclude_infra=not args.keep_infra,
    )
    print(
        json.dumps(
            {
                "run_dir": summary.run_dir,
                "crash_records": summary.crash_records,
                "infra_excluded_records": summary.infra_excluded_records,
                "unique_crashes": summary.unique_crashes,
                "clusters": [
                    {
                        "target_id": cluster.target_id,
                        "count": cluster.count,
                        "signature": cluster.signature,
                        "representative_work_dir": cluster.representative_work_dir,
                    }
                    for cluster in summary.clusters
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _cmd_build_template_feedback(args: argparse.Namespace) -> int:
    profile = build_feedback_profile(
        args.run_dir,
        max_cases_per_kind=args.max_cases_per_kind,
    )
    write_feedback_profile(profile, args.output)
    print(
        json.dumps(
            {
                "run_dir": args.run_dir,
                "output": args.output,
                "cups_seeds": len(profile.cups),
                "pwg_seeds": len(profile.pwg),
                "image_seeds": len(profile.images),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _cmd_build_output_feedback(args: argparse.Namespace) -> int:
    profile = build_output_feedback_profile(args.run_dir)
    write_output_feedback_profile(profile, args.output)
    print(
        json.dumps(
            {
                "run_dir": args.run_dir,
                "output": args.output,
                "formats": profile.format_counts,
                "structures": len(profile.structure_counts),
                "objectives": len(profile.objective_counts),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _cmd_export_template_seeds(args: argparse.Namespace) -> int:
    summary = export_template_seeds(
        run_dir=args.run_dir,
        output_dir=args.output_dir,
        target_ids=args.target_id,
        extensions=args.extension,
        limit=args.limit,
        include_crashes=args.include_crashes,
        include_ppd=args.include_ppd,
    )
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0 if summary.exported else 1


def _cmd_generate_template_seeds(args: argparse.Namespace) -> int:
    summary = generate_template_seeds(
        document_kind=args.document_kind,
        output_dir=args.output_dir,
        count=args.count,
        target_id=args.target_id,
        start_index=args.start_index,
        extensions=args.extension,
    )
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0 if summary.generated else 1


def _cmd_recover_run_summary(args: argparse.Namespace) -> int:
    summary = recover_run_summary(args.run_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _cmd_summarize_run_metrics(args: argparse.Namespace) -> int:
    payload = summarize_run_metrics(
        args.run_dir,
        afl_output_dir=args.afl_output_dir,
        llvm_coverage_json=args.llvm_coverage_json,
    )
    if args.output:
        write_run_metrics(payload, args.output)
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_summarize_loop_metrics(args: argparse.Namespace) -> int:
    payload = write_standard_loop_metrics(args.campaign_dir, output_path=args.output)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_summarize_run_set(args: argparse.Namespace) -> int:
    payload = summarize_run_set(args.root)
    write_run_set_metrics(payload, args.output, args.output_md)
    if args.output_md:
        print(render_run_set_markdown(payload))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_oss_fuzz_status(args: argparse.Namespace) -> int:
    status = inspect_oss_fuzz_cups_filters(args.oss_fuzz_dir)
    print(json.dumps(status.to_dict(), indent=2, sort_keys=True))
    return 0 if status.project_exists else 1


def _cmd_compare_baseline_metrics(args: argparse.Namespace) -> int:
    result = run_local_baseline_comparison(
        config_path=args.config,
        work_root=args.work_root,
        oss_fuzz_dir=args.oss_fuzz_dir,
        duration_sec=args.duration_sec,
        workers=args.workers,
        timeout_sec=args.timeout_sec,
        max_run_gb=args.max_run_gb,
        enable_llvm_profiles=args.enable_llvm_profiles,
        export_llvm_coverage=args.export_llvm_coverage,
        optimized_policy=args.optimized_policy,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_auto_expand(args: argparse.Namespace) -> int:
    plan = build_auto_expand_plan(
        search_root=args.search_root,
        output_profile=args.output_profile,
        max_runs=args.max_runs,
        max_cases_per_kind=args.max_cases_per_kind,
        stale_window=args.stale_window,
        duration_sec=args.duration_sec,
        workers=args.workers,
        timeout_sec=args.timeout_sec,
        max_run_gb=args.max_run_gb,
        skip_probe_rate=args.skip_probe_rate,
    )
    if args.plan_output:
        write_auto_expand_plan(plan, args.plan_output)
    print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_mine_source_constraints(args: argparse.Namespace) -> int:
    profile = mine_source_constraints(args.source_dir, max_records=args.max_records)
    write_source_constraint_profile(profile, args.output)
    print(json.dumps(profile["summary"], indent=2, sort_keys=True))
    return 0


def _cmd_summarize_dynamic_constraints(args: argparse.Namespace) -> int:
    profile = build_dynamic_compare_profile(args.run_dir, max_records=args.max_records)
    write_dynamic_compare_profile(profile, args.output)
    print(json.dumps(profile["summary"], indent=2, sort_keys=True))
    return 0


def _build_afl_plan_from_args(args: argparse.Namespace):
    return build_afl_plan(
        root=args.root,
        configs_dir=args.configs,
        target_id=args.target,
        config_ref=args.config,
        binary=args.binary,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        timeout_ms=args.timeout_ms,
        memory_mb=args.memory_mb,
        duration_sec=args.duration_sec,
    )


def _load_event(path: str | Path) -> BranchEvent:
    with Path(path).open("r", encoding="utf-8") as handle:
        return BranchEvent.from_dict(json.load(handle))


def _verify_hash(event: BranchEvent, input_path: Path) -> None:
    actual = sha256_file(input_path)
    if actual != event.input_sha256:
        raise SystemExit(f"input hash mismatch: expected {event.input_sha256}, got {actual}")


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _add_afl_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", default=".")
    parser.add_argument("--configs", default="configs")
    parser.add_argument("--target", required=True)
    parser.add_argument("--config", required=True, help="A0-A4 id or config name")
    parser.add_argument("--binary", required=True, help="AFL-instrumented target binary")
    parser.add_argument("--input-dir", help="use this seed directory instead of preparing one from configs/afl.yaml")
    parser.add_argument("--output-dir", help="write AFL++ output here instead of configs/afl.yaml default")
    parser.add_argument("--duration-sec", type=int, help="add AFL++ -V duration seconds")
    parser.add_argument("--timeout-ms", type=int, help="override AFL++ -t timeout in milliseconds")
    parser.add_argument("--memory-mb", help="override AFL++ -m memory limit; use 'none' when appropriate")


def _shell_quote(value: str) -> str:
    if value.replace("_", "").replace("-", "").replace("/", "").replace(".", "").replace(",", "").isalnum():
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
