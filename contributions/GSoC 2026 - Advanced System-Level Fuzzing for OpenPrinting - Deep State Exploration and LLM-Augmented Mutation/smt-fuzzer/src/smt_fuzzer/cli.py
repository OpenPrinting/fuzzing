from __future__ import annotations

import argparse
import json
from pathlib import Path

from .afl import afl_build_env, build_afl_plan, print_afl_plan, run_afl_plan
from .arithmetic_explorer import run_arithmetic_explore
from .crash_dedup import dedup_run
from .experiment import estimate_cpu_hours, load_experiment_rows
from .hashing import sha256_file
from .models import BranchEvent
from .multitarget_runner import run_multitarget_monitor
from .patcher import apply_solver_result, load_solver_result, write_solver_result
from .solver import MissingSolverError, condition_holds, read_event_value, solve_event
from .validation import validate_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smt-fuzzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate project configs")
    validate_parser.add_argument("--configs", default="configs")

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

    afl_env_parser = subparsers.add_parser("afl-build-env", help="print AFL++ compiler environment")
    afl_env_parser.add_argument("--configs", default="configs")
    afl_env_parser.add_argument("--json", action="store_true")

    multitarget_parser = subparsers.add_parser(
        "multitarget-monitor",
        help="run multi-target PPD+document monitoring harness",
    )
    multitarget_parser.add_argument("--config", default="configs/parser_targets.yaml")
    multitarget_parser.add_argument("--work-root", default="work/multitarget")
    multitarget_parser.add_argument("--workers", type=int, default=4)
    multitarget_parser.add_argument("--cases-per-target", type=int)
    multitarget_parser.add_argument("--duration-sec", type=int)
    multitarget_parser.add_argument("--timeout-sec", type=int, default=15)
    multitarget_parser.add_argument("--discard-stdout", action="store_true")
    multitarget_parser.add_argument("--discovery-mode", choices=["crash", "coverage"], default="crash")

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
    parser.error(f"unknown command: {args.command}")
    return 2


def _cmd_validate(args: argparse.Namespace) -> int:
    issues = validate_all(args.configs)
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
        return run_afl_plan(plan, execute=True)
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
        "PYTHONPATH=src python3 -m smt_fuzzer.cli multitarget-monitor "
        f"--config {_shell_quote(args.config)} "
        f"--work-root {_shell_quote(args.work_root)} "
        f"--workers {args.workers} "
        f"--timeout-sec {args.timeout_sec}"
    )
    if args.cases_per_target is not None:
        run_command += f" --cases-per-target {args.cases_per_target}"
    if args.duration_sec is not None:
        run_command += f" --duration-sec {args.duration_sec}"
    if args.discard_stdout:
        run_command += " --discard-stdout"
    if args.discovery_mode != "crash":
        run_command += f" --discovery-mode {args.discovery_mode}"
    summary = run_multitarget_monitor(
        config_path=args.config,
        work_root=args.work_root,
        workers=args.workers,
        cases_per_target=args.cases_per_target,
        duration_sec=args.duration_sec,
        timeout_sec=args.timeout_sec,
        run_command=run_command,
        capture_stdout=not args.discard_stdout,
        discovery_mode=args.discovery_mode,
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


def _build_afl_plan_from_args(args: argparse.Namespace):
    return build_afl_plan(
        root=args.root,
        configs_dir=args.configs,
        target_id=args.target,
        config_ref=args.config,
        binary=args.binary,
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


def _shell_quote(value: str) -> str:
    if value.replace("_", "").replace("-", "").replace("/", "").replace(".", "").replace(",", "").isalnum():
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
