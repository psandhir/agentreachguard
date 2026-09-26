from pathlib import Path

import pytest

from horustrace.limits import (
    MAX_FILE_SIZE_BYTES,
    MAX_JSON_BYTES,
    MAX_YAML_ALIAS_COUNT,
    MAX_YAML_BYTES,
    MAX_YAML_NESTING,
)
from horustrace.scanner import ScannerError, scan


def test_oversized_source_is_skipped_with_coverage_diagnostic(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_bytes(b"#" * (MAX_FILE_SIZE_BYTES + 1))
    graph, _ = scan(tmp_path)
    assert graph.coverage.incomplete
    assert graph.coverage.files_failed == 1
    assert graph.coverage.diagnostics[0].kind == "unsupported_security_construct"


def test_oversized_mcp_configuration_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_bytes(b"{" + b"x" * MAX_JSON_BYTES + b"}")
    with pytest.raises(ScannerError, match="security configuration"):
        scan(tmp_path)


def test_alias_heavy_manifest_fails_closed(tmp_path: Path) -> None:
    aliases = ", ".join("*base" for _ in range(MAX_YAML_ALIAS_COUNT + 1))
    (tmp_path / "horustrace.manifest.yaml").write_text(
        f"base: &base value\nvalues: [{aliases}]\n"
    )
    with pytest.raises(ScannerError, match="alias limit"):
        scan(tmp_path)


def test_deep_yaml_manifest_fails_closed(tmp_path: Path) -> None:
    nested = "value"
    for _ in range(MAX_YAML_NESTING + 2):
        nested = f"[ {nested} ]"
    (tmp_path / "horustrace.manifest.yaml").write_text(
        f"version: 1\nextra: {nested}\n", encoding="utf-8"
    )
    with pytest.raises(ScannerError, match="nesting limit"):
        scan(tmp_path)


def test_oversized_yaml_manifest_fails_closed(tmp_path: Path) -> None:
    payload = "#" * (MAX_YAML_BYTES + 1)
    (tmp_path / "horustrace.manifest.yaml").write_text(payload, encoding="utf-8")
    with pytest.raises(ScannerError, match="size limit"):
        scan(tmp_path)


def test_malformed_utf8_source_becomes_incomplete_coverage(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_bytes(b"from google.adk import Agent\n\xff\xfe\n")
    graph, _ = scan(tmp_path)
    assert graph.coverage.incomplete
    assert any(diagnostic.kind == "parse_error" for diagnostic in graph.coverage.diagnostics)


def test_traversal_limit_aborts_safely(tmp_path: Path, monkeypatch) -> None:
    from horustrace import scanner

    for index in range(3):
        (tmp_path / f"file{index}.txt").write_text("x")
    monkeypatch.setattr(scanner, "MAX_REPOSITORY_ENTRIES_VISITED", 2)
    with pytest.raises(ScannerError, match="traversal"):
        scan(tmp_path)
