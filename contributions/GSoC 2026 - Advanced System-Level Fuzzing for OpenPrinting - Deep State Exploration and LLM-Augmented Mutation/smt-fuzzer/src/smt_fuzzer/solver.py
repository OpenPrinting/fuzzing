from __future__ import annotations

import time
from typing import Callable

from .models import BranchEvent, Patch, SolverResult


class MissingSolverError(RuntimeError):
    pass


def read_event_value(event: BranchEvent, input_bytes: bytes) -> int:
    end = event.offset + event.width
    if end > len(input_bytes):
        raise ValueError(
            f"event reads bytes [{event.offset}, {end}), but input has {len(input_bytes)} bytes"
        )
    return int.from_bytes(input_bytes[event.offset:end], event.endianness, signed=False)


def _signed_value(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value & sign_bit else value


def condition_holds(event: BranchEvent, value: int) -> bool:
    bits = event.width * 8
    mask = (1 << bits) - 1
    lhs_unsigned = value & mask
    rhs_unsigned = event.rhs & mask
    lhs_signed = _signed_value(value, bits)
    rhs_signed = _signed_value(event.rhs, bits)

    checks: dict[str, Callable[[], bool]] = {
        "eq": lambda: lhs_unsigned == rhs_unsigned,
        "ne": lambda: lhs_unsigned != rhs_unsigned,
        "ult": lambda: lhs_unsigned < rhs_unsigned,
        "ule": lambda: lhs_unsigned <= rhs_unsigned,
        "ugt": lambda: lhs_unsigned > rhs_unsigned,
        "uge": lambda: lhs_unsigned >= rhs_unsigned,
        "slt": lambda: lhs_signed < rhs_signed,
        "sle": lambda: lhs_signed <= rhs_signed,
        "sgt": lambda: lhs_signed > rhs_signed,
        "sge": lambda: lhs_signed >= rhs_signed,
    }
    return checks[event.op]()


def solve_event(event: BranchEvent, input_bytes: bytes, *, allow_fallback: bool = False) -> SolverResult:
    start = time.perf_counter()
    old_value = read_event_value(event, input_bytes)
    if condition_holds(event, old_value):
        return SolverResult(
            status="already_satisfied",
            solver_ms=_elapsed_ms(start),
            patches=[],
            reason="input already satisfies branch event",
            event=event,
        )

    try:
        patch_value = _solve_with_z3(event)
        backend = "z3"
    except MissingSolverError:
        if not allow_fallback:
            raise
        patch_value = _solve_by_bounded_search(event)
        backend = "bounded-fallback"

    if patch_value is None:
        return SolverResult(
            status="unsat",
            solver_ms=_elapsed_ms(start),
            patches=[],
            reason=f"no value found by {backend}",
            event=event,
        )

    old_bytes = old_value.to_bytes(event.width, event.endianness, signed=False)
    new_bytes = patch_value.to_bytes(event.width, event.endianness, signed=False)
    return SolverResult(
        status="sat",
        solver_ms=_elapsed_ms(start),
        patches=[
            Patch(
                offset=event.offset,
                old_hex=old_bytes.hex(),
                new_hex=new_bytes.hex(),
                width=event.width,
            )
        ],
        reason=f"solved with {backend}",
        event=event,
    )


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 3)


def _solve_with_z3(event: BranchEvent) -> int | None:
    try:
        import z3  # type: ignore
    except ImportError as exc:
        raise MissingSolverError(
            "z3-solver is not installed. Install project dependencies with "
            "`python3 -m pip install -r requirements.txt`."
        ) from exc

    bits = event.width * 8
    mask = (1 << bits) - 1
    field = z3.BitVec("field", bits)
    rhs = z3.BitVecVal(event.rhs & mask, bits)
    solver = z3.Solver()
    solver.add(_z3_constraint(z3, field, rhs, event.op))
    result = solver.check()
    if result != z3.sat:
        return None
    model_value = solver.model()[field]
    if model_value is None:
        return None
    return int(model_value.as_long()) & mask


def _z3_constraint(z3_module, lhs, rhs, op: str):
    if op == "eq":
        return lhs == rhs
    if op == "ne":
        return lhs != rhs
    if op == "ult":
        return z3_module.ULT(lhs, rhs)
    if op == "ule":
        return z3_module.ULE(lhs, rhs)
    if op == "ugt":
        return z3_module.UGT(lhs, rhs)
    if op == "uge":
        return z3_module.UGE(lhs, rhs)
    if op == "slt":
        return lhs < rhs
    if op == "sle":
        return lhs <= rhs
    if op == "sgt":
        return lhs > rhs
    if op == "sge":
        return lhs >= rhs
    raise ValueError(f"unsupported op: {op}")


def _solve_by_bounded_search(event: BranchEvent) -> int | None:
    bits = event.width * 8
    max_value = 1 << bits
    if bits <= 16:
        candidates = range(max_value)
    else:
        candidates = _wide_candidates(event, max_value)
    for candidate in candidates:
        if condition_holds(event, candidate):
            return candidate
    return None


def _wide_candidates(event: BranchEvent, max_value: int) -> list[int]:
    mask = max_value - 1
    rhs = event.rhs & mask
    sign_bit = 1 << (event.width * 8 - 1)
    candidates = {
        0,
        1,
        mask,
        rhs,
        (rhs - 1) & mask,
        (rhs + 1) & mask,
        sign_bit,
        (sign_bit - 1) & mask,
        (sign_bit + 1) & mask,
    }
    return sorted(candidates)
