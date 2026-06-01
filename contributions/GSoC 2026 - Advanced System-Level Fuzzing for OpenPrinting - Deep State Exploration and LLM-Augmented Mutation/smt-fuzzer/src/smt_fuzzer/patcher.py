from __future__ import annotations

import json
from pathlib import Path

from .hashing import sha256_bytes, sha256_file
from .models import Patch, SolverResult


def apply_patches(input_bytes: bytes, patches: list[Patch]) -> bytes:
    output = bytearray(input_bytes)
    for patch in patches:
        start = patch.offset
        end = patch.offset + patch.width
        if end > len(output):
            raise ValueError(f"patch [{start}, {end}) exceeds input length {len(output)}")
        old_bytes = bytes.fromhex(patch.old_hex)
        current = bytes(output[start:end])
        if current != old_bytes:
            raise ValueError(
                f"patch old bytes mismatch at offset {start}: "
                f"expected {old_bytes.hex()}, got {current.hex()}"
            )
        output[start:end] = bytes.fromhex(patch.new_hex)
    return bytes(output)


def load_solver_result(path: str | Path) -> SolverResult:
    with Path(path).open("r", encoding="utf-8") as handle:
        return SolverResult.from_dict(json.load(handle))


def write_solver_result(result: SolverResult, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")


def apply_solver_result(
    result: SolverResult,
    input_path: str | Path,
    output_dir: str | Path,
) -> Path:
    source = Path(input_path)
    input_bytes = source.read_bytes()
    expected_hash = result.event.input_sha256
    actual_hash = sha256_file(source)
    if actual_hash != expected_hash:
        raise ValueError(f"input hash mismatch: expected {expected_hash}, got {actual_hash}")

    output_bytes = apply_patches(input_bytes, result.patches)
    output_hash = sha256_bytes(output_bytes)[:12]
    target = result.event.target_id.replace("/", "_")
    output_name = f"smt-{target}-{expected_hash[:12]}-{output_hash}.bin"
    destination = Path(output_dir) / output_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(output_bytes)
    return destination
