from __future__ import annotations

import concurrent.futures
import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .document_harness import make_pwg_raster
from .ppd_templates import make_pwg_resolution_ppd


UINT32 = 2**32 - 1
MOD32 = 2**32


@dataclass(frozen=True)
class ArithmeticParams:
    case_id: int
    output_dpi: int
    input_x_dpi: int
    input_y_dpi: int
    width: int
    height: int
    bits_per_pixel: int
    bytes_per_line: int
    y_factor: int
    product_mod32: int
    strategy: str


@dataclass(frozen=True)
class ArithmeticResult:
    case_id: int
    work_dir: str
    ppd_path: str
    document_path: str
    command_path: str
    stderr_path: str
    stdout_path: str
    meta_path: str
    params: ArithmeticParams
    cupstestppd_ok: bool
    returncode: int | None
    timed_out: bool
    crashed: bool
    oracle: str
    reject_reason: str
    duration_ms: float


@dataclass(frozen=True)
class ArithmeticSummary:
    run_id: str
    work_dir: str
    duration_budget_sec: int
    elapsed_sec: float
    workers: int
    cases: int
    crashes: int
    valid_ppds: int
    timeouts: int
    reject_reasons: dict[str, int]
    results: list[ArithmeticResult]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def concise_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "work_dir": self.work_dir,
            "duration_budget_sec": self.duration_budget_sec,
            "elapsed_sec": self.elapsed_sec,
            "workers": self.workers,
            "cases": self.cases,
            "crashes": self.crashes,
            "valid_ppds": self.valid_ppds,
            "timeouts": self.timeouts,
            "reject_reasons": self.reject_reasons,
        }


def iter_arithmetic_params() -> Iterable[ArithmeticParams]:
    case_id = 0
    widths = [5, 8, 11, 16, 31, 64, 1, 2, 3, 4, 7, 13, 127, 256]
    heights = [1, 2, 4, 6, 8]
    bits_per_pixels = [16, 24, 32, 8, 1]
    output_dpis = [1, 2, 3, 4, 5, 8, 10, 16, 72, 75, 100, 150, 300, 600, 1200]
    generic_factors = [1, 2, 4, 8, 16, 64, 256, 1024, 65536, 2**20, 2**24, 2**28, 2**31]

    for width in widths:
        for bits_per_pixel in bits_per_pixels:
            bytes_per_line = max(1, (width * bits_per_pixel + 7) // 8)
            risk_factors = _risk_factors(bytes_per_line)
            for output_dpi in [1, 2, 4, 8, 16]:
                for factor in risk_factors:
                    input_y_dpi = output_dpi * factor
                    if input_y_dpi < 1 or input_y_dpi > UINT32:
                        continue
                    for height in heights:
                        yield _make_params(
                            case_id=case_id,
                            output_dpi=output_dpi,
                            input_y_dpi=input_y_dpi,
                            width=width,
                            height=height,
                            bits_per_pixel=bits_per_pixel,
                            bytes_per_line=bytes_per_line,
                            factor=factor,
                        )
                        case_id += 1

    while True:
        for width in widths:
            for bits_per_pixel in bits_per_pixels:
                bytes_per_line = max(1, (width * bits_per_pixel + 7) // 8)
                factors = sorted(set(generic_factors + _overflow_factors(bytes_per_line)))
                for output_dpi in output_dpis:
                    for factor in factors:
                        input_y_dpi = output_dpi * factor
                        if input_y_dpi < 1 or input_y_dpi > UINT32:
                            continue
                        yield _make_params(
                            case_id=case_id,
                            output_dpi=output_dpi,
                            input_y_dpi=input_y_dpi,
                            width=width,
                            height=heights[case_id % len(heights)],
                            bits_per_pixel=bits_per_pixel,
                            bytes_per_line=bytes_per_line,
                            factor=factor,
                        )
                        case_id += 1


def run_arithmetic_explore(
    *,
    work_dir: str | Path,
    duration_sec: int,
    workers: int,
    timeout_sec: int,
    filter_binary: str = "/usr/lib/cups/filter/pwgtoraster",
) -> ArithmeticSummary:
    run_id = time.strftime("%Y%m%d-%H%M%S")
    root = Path(work_dir) / run_id
    root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + duration_sec
    param_iter = iter_arithmetic_params()
    results: list[ArithmeticResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures: set[concurrent.futures.Future[ArithmeticResult]] = set()
        while time.monotonic() < deadline or futures:
            while time.monotonic() < deadline and len(futures) < workers:
                params = next(param_iter)
                case_dir = root / "cases" / f"case-{params.case_id:06d}"
                futures.add(executor.submit(run_arithmetic_case, params, case_dir, filter_binary, timeout_sec))
            if not futures:
                break
            done, futures = concurrent.futures.wait(
                futures,
                timeout=max(0.1, min(1.0, deadline - time.monotonic())),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                results.append(future.result())

    results.sort(key=lambda item: item.case_id)
    reject_reasons: dict[str, int] = {}
    for result in results:
        reject_reasons[result.reject_reason] = reject_reasons.get(result.reject_reason, 0) + 1

    summary = ArithmeticSummary(
        run_id=run_id,
        work_dir=str(root),
        duration_budget_sec=duration_sec,
        elapsed_sec=round(time.monotonic() - started, 3),
        workers=workers,
        cases=len(results),
        crashes=sum(1 for result in results if result.crashed),
        valid_ppds=sum(1 for result in results if result.cupstestppd_ok),
        timeouts=sum(1 for result in results if result.timed_out),
        reject_reasons=dict(sorted(reject_reasons.items())),
        results=results,
    )
    (root / "summary.json").write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "summary.concise.json").write_text(
        json.dumps(summary.concise_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def run_arithmetic_case(
    params: ArithmeticParams,
    case_dir: Path,
    filter_binary: str,
    timeout_sec: int,
) -> ArithmeticResult:
    case_dir.mkdir(parents=True, exist_ok=True)
    ppd_path = case_dir / "candidate.ppd"
    document_path = case_dir / "document.pwg"
    command_path = case_dir / "command.txt"
    stdout_path = case_dir / "stdout.bin"
    stderr_path = case_dir / "stderr.txt"
    meta_path = case_dir / "meta.json"

    ppd_path.write_text(make_pwg_resolution_ppd(params.output_dpi), encoding="utf-8")
    document_path.write_bytes(
        make_pwg_raster(
            width=params.width,
            height=params.height,
            bits_per_pixel=params.bits_per_pixel,
            x_res=params.input_x_dpi,
            y_res=params.input_y_dpi,
        )
    )

    cupstestppd_ok = _run_cupstestppd(ppd_path, case_dir / "cupstestppd.txt")
    command = [filter_binary, "1", "smt", "smt", "1", "", str(document_path)]
    command_path.write_text(f"PPD={shlex.quote(str(ppd_path))} {shlex.join(command)}\n", encoding="utf-8")

    started = time.perf_counter()
    stderr_text = ""
    returncode: int | None = None
    timed_out = False
    try:
        with stdout_path.open("wb") as stdout:
            completed = subprocess.run(
                command,
                stdout=stdout,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec,
                check=False,
                env=_build_env(ppd_path),
            )
        returncode = completed.returncode
        stderr_text = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stderr_text = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    stderr_path.write_text(stderr_text, encoding="utf-8")
    crashed, oracle = _classify(returncode, timed_out, stderr_text)
    reject_reason = _reject_reason(stderr_text, returncode, timed_out, crashed)

    result = ArithmeticResult(
        case_id=params.case_id,
        work_dir=str(case_dir),
        ppd_path=str(ppd_path),
        document_path=str(document_path),
        command_path=str(command_path),
        stderr_path=str(stderr_path),
        stdout_path=str(stdout_path),
        meta_path=str(meta_path),
        params=params,
        cupstestppd_ok=cupstestppd_ok,
        returncode=returncode,
        timed_out=timed_out,
        crashed=crashed,
        oracle=oracle,
        reject_reason=reject_reason,
        duration_ms=duration_ms,
    )
    meta_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _overflow_factors(bytes_per_line: int) -> list[int]:
    center = MOD32 // bytes_per_line
    values = []
    for delta in [-3, -2, -1, 0, 1, 2, 3]:
        if center + delta > 0:
            values.append(center + delta)
    return values


def _risk_factors(bytes_per_line: int) -> list[int]:
    values = [2**31]
    values.extend(_overflow_factors(bytes_per_line))
    return sorted(set(value for value in values if value > 0), reverse=True)


def _make_params(
    *,
    case_id: int,
    output_dpi: int,
    input_y_dpi: int,
    width: int,
    height: int,
    bits_per_pixel: int,
    bytes_per_line: int,
    factor: int,
) -> ArithmeticParams:
    strategy = "overflow-near" if (bytes_per_line * factor) >= MOD32 else "scale-sweep"
    return ArithmeticParams(
        case_id=case_id,
        output_dpi=output_dpi,
        input_x_dpi=output_dpi,
        input_y_dpi=input_y_dpi,
        width=width,
        height=height,
        bits_per_pixel=bits_per_pixel,
        bytes_per_line=bytes_per_line,
        y_factor=factor,
        product_mod32=(bytes_per_line * factor) % MOD32,
        strategy=strategy,
    )


def _run_cupstestppd(ppd_path: Path, output_path: Path) -> bool:
    completed = subprocess.run(
        ["cupstestppd", "-W", "none", str(ppd_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output_path.write_text(completed.stdout, encoding="utf-8")
    return completed.returncode == 0


def _build_env(ppd_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PPD"] = str(ppd_path)
    return env


def _classify(returncode: int | None, timed_out: bool, stderr_text: str) -> tuple[bool, str]:
    text = stderr_text.lower()
    if timed_out:
        return False, "timeout"
    if "addresssanitizer" in text or "segmentation fault" in text or "crashed on signal" in text:
        return True, "stderr crash/sanitizer"
    if returncode is not None and returncode < 0:
        return True, f"signal {-returncode}"
    if returncode in {86, 134, 139}:
        return True, f"returncode {returncode}"
    return False, ""


def _reject_reason(stderr_text: str, returncode: int | None, timed_out: bool, crashed: bool) -> str:
    text = stderr_text.lower()
    if timed_out:
        return "timeout"
    if crashed:
        return "crash"
    if "not an integer multiple" in text:
        return "resolution-not-multiple"
    if "bad raster data" in text:
        return "bad-raster-data"
    if "unsupported" in text:
        return "unsupported"
    if returncode == 0:
        return "ok"
    return f"returncode-{returncode}"
