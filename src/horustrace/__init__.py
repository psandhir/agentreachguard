"""HorusTrace public package namespace.

The v0.4 migration preserves the original agentreachguard implementation package
for backward compatibility while exposing the preferred horustrace namespace.
"""

from __future__ import annotations

import importlib
import sys

from agentreachguard import __version__

_ALIASES = (
    "adapters",
    "adg",
    "aibom",
    "analysis",
    "benchmark",
    "config",
    "coverage",
    "flow",
    "heuristics",
    "limits",
    "manifest_schema",
    "models",
    "path_safety",
    "provenance",
    "reporters",
    "rule_registry",
    "rules",
    "scanner",
    "suppressions",
)

for _name in _ALIASES:
    sys.modules[f"{__name__}.{_name}"] = importlib.import_module(
        f"agentreachguard.{_name}"
    )

del importlib, sys, _name

__all__ = ["__version__"]
