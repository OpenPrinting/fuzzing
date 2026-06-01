"""Source-tree compatibility package.

This shim lets `python3 -m smt_fuzzer.cli` work from a checkout without an
editable install. Packaged installs use the real package under `src/`.
"""

from __future__ import annotations

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "smt_fuzzer"
if _SRC_PACKAGE.exists():
    __path__.append(str(_SRC_PACKAGE))  # type: ignore[name-defined]
