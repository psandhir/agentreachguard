"""Canonical-path containment for scans of untrusted repositories."""

from __future__ import annotations

from pathlib import Path


def canonical_root(path: Path) -> Path:
    """Return the canonical directory boundary for a scan target."""
    resolved = path.resolve()
    return resolved if resolved.is_dir() else resolved.parent


def is_within_root(path: Path, root: Path) -> bool:
    """True when path resolves inside root, including root itself."""
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True
