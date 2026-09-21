from __future__ import annotations

from pathlib import Path

import pytest

import agentreachguard
import horustrace
from agentreachguard.adapters.manifest import MANIFEST_FILENAMES
from agentreachguard.config import ConfigError, load_config
from agentreachguard.scanner import _ignored
from agentreachguard.suppressions import SUPPRESSION_FILENAMES
from horustrace.models import Graph as HorusGraph
from agentreachguard.models import Graph as LegacyGraph


def _write_config(path: Path) -> None:
    path.write_text("version: 1\nscanner:\n  strict: true\n", encoding="utf-8")


def test_horustrace_public_namespace_maps_to_legacy_engine() -> None:
    assert horustrace.__version__ == agentreachguard.__version__
    assert HorusGraph is LegacyGraph


def test_horustrace_config_filename_is_supported(tmp_path: Path) -> None:
    config = tmp_path / ".horustrace.yaml"
    _write_config(config)

    loaded = load_config(tmp_path)

    assert loaded.strict is True
    assert loaded.source_path == config


def test_legacy_config_filename_remains_supported(tmp_path: Path) -> None:
    config = tmp_path / ".agentreachguard.yaml"
    _write_config(config)

    loaded = load_config(tmp_path)

    assert loaded.strict is True
    assert loaded.source_path == config


def test_dual_default_config_files_fail_closed(tmp_path: Path) -> None:
    _write_config(tmp_path / ".horustrace.yaml")
    _write_config(tmp_path / ".agentreachguard.yaml")

    with pytest.raises(ConfigError, match="multiple default scanner configuration files"):
        load_config(tmp_path)


def test_new_and_legacy_policy_filenames_are_supported() -> None:
    assert "horustrace.manifest.yaml" in MANIFEST_FILENAMES
    assert "agentreachguard.manifest.yaml" in MANIFEST_FILENAMES
    assert ".horustrace.suppressions.yaml" in SUPPRESSION_FILENAMES
    assert ".agentreachguard.suppressions.yaml" in SUPPRESSION_FILENAMES


@pytest.mark.parametrize("marker", [".horustrace-ignore", ".agentreachguard-ignore"])
def test_new_and_legacy_ignore_markers_are_supported(tmp_path: Path, marker: str) -> None:
    subtree = tmp_path / "ignored"
    subtree.mkdir()
    (subtree / marker).write_text("", encoding="utf-8")
    candidate = subtree / "agent.py"
    candidate.write_text("x = 1\n", encoding="utf-8")

    assert _ignored(candidate, tmp_path)
