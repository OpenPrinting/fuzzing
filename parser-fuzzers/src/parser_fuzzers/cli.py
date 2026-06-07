"""Compatibility wrapper for :mod:`parser_fuzzers.runner.cli`."""

from __future__ import annotations

from importlib import import_module as _import_module

_impl = _import_module("parser_fuzzers.runner.cli")
globals().update(
    {
        key: value
        for key, value in _impl.__dict__.items()
        if key not in {"__name__", "__package__", "__loader__", "__spec__"}
    }
)

if __name__ == "__main__":
    raise SystemExit(_impl.main())
