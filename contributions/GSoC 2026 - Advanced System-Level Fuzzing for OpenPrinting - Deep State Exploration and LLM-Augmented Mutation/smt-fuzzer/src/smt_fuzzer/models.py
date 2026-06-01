from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


SUPPORTED_OPS = {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}
SUPPORTED_WIDTHS = {1, 2, 4, 8}


def coerce_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field_name} must be an integer or integer string")


@dataclass(frozen=True)
class BranchEvent:
    target_id: str
    input_path: str
    input_sha256: str
    offset: int
    width: int
    endianness: str
    signed: bool
    op: str
    rhs: int
    description: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BranchEvent":
        required = {
            "target_id",
            "input_path",
            "input_sha256",
            "offset",
            "width",
            "endianness",
            "signed",
            "op",
            "rhs",
            "description",
        }
        missing = sorted(required - data.keys())
        if missing:
            raise ValueError(f"branch event missing required fields: {', '.join(missing)}")

        event = cls(
            target_id=str(data["target_id"]),
            input_path=str(data["input_path"]),
            input_sha256=str(data["input_sha256"]),
            offset=coerce_int(data["offset"], "offset"),
            width=coerce_int(data["width"], "width"),
            endianness=str(data["endianness"]),
            signed=bool(data["signed"]),
            op=str(data["op"]),
            rhs=coerce_int(data["rhs"], "rhs"),
            description=str(data["description"]),
        )
        event.validate()
        return event

    def validate(self) -> None:
        if not self.target_id:
            raise ValueError("target_id must not be empty")
        if self.offset < 0:
            raise ValueError("offset must be non-negative")
        if self.width not in SUPPORTED_WIDTHS:
            raise ValueError(f"width must be one of {sorted(SUPPORTED_WIDTHS)}")
        if self.endianness not in {"little", "big"}:
            raise ValueError("endianness must be 'little' or 'big'")
        if self.op not in SUPPORTED_OPS:
            raise ValueError(f"op must be one of {sorted(SUPPORTED_OPS)}")
        if len(self.input_sha256) != 64:
            raise ValueError("input_sha256 must be a 64-character hex digest")
        int(self.input_sha256, 16)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Patch:
    offset: int
    old_hex: str
    new_hex: str
    width: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Patch":
        required = {"offset", "old_hex", "new_hex", "width"}
        missing = sorted(required - data.keys())
        if missing:
            raise ValueError(f"patch missing required fields: {', '.join(missing)}")
        patch = cls(
            offset=coerce_int(data["offset"], "patch.offset"),
            old_hex=str(data["old_hex"]),
            new_hex=str(data["new_hex"]),
            width=coerce_int(data["width"], "patch.width"),
        )
        patch.validate()
        return patch

    def validate(self) -> None:
        if self.offset < 0:
            raise ValueError("patch offset must be non-negative")
        if self.width not in SUPPORTED_WIDTHS:
            raise ValueError(f"patch width must be one of {sorted(SUPPORTED_WIDTHS)}")
        expected_hex_len = self.width * 2
        if len(self.old_hex) != expected_hex_len or len(self.new_hex) != expected_hex_len:
            raise ValueError("patch hex strings must match width")
        bytes.fromhex(self.old_hex)
        bytes.fromhex(self.new_hex)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SolverResult:
    status: str
    solver_ms: float
    patches: list[Patch]
    reason: str
    event: BranchEvent

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SolverResult":
        required = {"status", "solver_ms", "patches", "reason", "event"}
        missing = sorted(required - data.keys())
        if missing:
            raise ValueError(f"solver result missing required fields: {', '.join(missing)}")
        return cls(
            status=str(data["status"]),
            solver_ms=float(data["solver_ms"]),
            patches=[Patch.from_dict(item) for item in data["patches"]],
            reason=str(data["reason"]),
            event=BranchEvent.from_dict(data["event"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "solver_ms": self.solver_ms,
            "patches": [patch.to_dict() for patch in self.patches],
            "reason": self.reason,
            "event": self.event.to_dict(),
        }
