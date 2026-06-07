"""Compatibility wrapper for :mod:`parser_fuzzers.metrics.baseline_compare`."""

from __future__ import annotations

import sys as _sys
from importlib import import_module as _import_module

_impl = _import_module("parser_fuzzers.metrics.baseline_compare")
_sys.modules[__name__] = _impl
