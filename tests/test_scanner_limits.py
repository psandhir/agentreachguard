from pathlib import Path

import pytest

from agentreachguard.limits import MAX_FILE_SIZE_BYTES, MAX_JSON_BYTES, MAX_YAML_ALIAS_COUNT
from agentreachguard.scanner import ScannerError, scan


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
    (tmp_path / "agentreachguard.manifest.yaml").write_text(
        f"base: &base value\nvalues: [{aliases}]\n"
    )
    with pytest.raises(ScannerError, match="alias limit"):
        scan(tmp_path)


def test_traversal_limit_aborts_safely(tmp_path: Path, monkeypatch) -> None:
    from agentreachguard import scanner

    for index in range(3):
        (tmp_path / f"file{index}.txt").write_text("x")
    monkeypatch.setattr(scanner, "MAX_FILES_VISITED", 2)
    with pytest.raises(ScannerError, match="traversal"):
        scan(tmp_path)
