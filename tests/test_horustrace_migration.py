from __future__ import annotations

from pathlib import Path

import pytest

import agentreachguard
import horustrace
from horustrace.adapters.manifest import MANIFEST_FILENAMES
from horustrace.config import ConfigError, load_config
from horustrace.scanner import IGNORE_MARKERS
from horustrace.suppressions import SUPPRESSION_FILENAMES


def _config(path: Path) -> None:
    path.write_text("version: 1\nscanner:\n  strict: true\n", encoding="utf-8")


def test_horustrace_and_legacy_packages_are_importable() -> None:
    assert horustrace.__version__ == agentreachguard.__version__


def test_new_config_filename_is_preferred_when_present(tmp_path: Path) -> None:
    path = tmp_path / ".horustrace.yaml"
    _config(path)
    config = load_config(tmp_path)
    assert config.strict is True
    assert config.source_path == path


def test_legacy_config_filename_remains_supported(tmp_path: Path) -> None:
    path = tmp_path / ".agentreachguard.yaml"
    _config(path)
    config = load_config(tmp_path)
    assert config.strict is True
    assert config.source_path == path


def test_dual_default_config_files_fail_closed(tmp_path: Path) -> None:
    _config(tmp_path / ".horustrace.yaml")
    _config(tmp_path / ".agentreachguard.yaml")
    with pytest.raises(ConfigError, match="multiple default configuration files"):
        load_config(tmp_path)


def test_manifest_and_suppression_legacy_names_remain_supported() -> None:
    assert "horustrace.manifest.yaml" in MANIFEST_FILENAMES
    assert "agentreachguard.manifest.yaml" in MANIFEST_FILENAMES
    assert ".horustrace.suppressions.yaml" in SUPPRESSION_FILENAMES
    assert ".agentreachguard.suppressions.yaml" in SUPPRESSION_FILENAMES


def test_ignore_markers_support_new_and_legacy_names() -> None:
    assert ".horustrace-ignore" in IGNORE_MARKERS
    assert ".agentreachguard-ignore" in IGNORE_MARKERS
