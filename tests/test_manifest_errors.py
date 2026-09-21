from pathlib import Path

import pytest

from horustrace.adapters.manifest import ManifestError, scan_manifest
from horustrace.cli import main
from horustrace.scanner import scan


@pytest.mark.parametrize("contents", [
    "agents: [", "", "[]", "false", "agents: invalid", "agents: [invalid]",
    "agent: invalid", "identities: invalid",
    "agents: [{name: agent, tools: invalid}]",
    "agents: [{name: agent, tools: [invalid]}]",
    "agents: [{name: agent, policy: invalid}]",
    "agents: [{name: agent, tools: [{resources: invalid}]}]",
])
def test_invalid_manifest_fails_scan(tmp_path: Path, contents):
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(contents, encoding="utf-8")
    with pytest.raises(ManifestError, match="invalid manifest"):
        scan(tmp_path)


@pytest.mark.parametrize("output_format", ["console", "json", "sarif"])
@pytest.mark.parametrize("fail_on", ["none", "high"])
def test_cli_errors_are_not_suppressed_by_severity_threshold(
    tmp_path: Path, capsys, output_format, fail_on,
):
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text('agents: [\n token: TOP_SECRET\n', encoding="utf-8")
    output = tmp_path / "report"
    assert main([
        "scan", str(tmp_path), "--format", output_format,
        "--fail-on", fail_on, "--output", str(output),
    ]) == 1
    captured = capsys.readouterr()
    assert str(manifest) in captured.err
    assert "invalid manifest YAML at line" in captured.err
    assert "TOP_SECRET" not in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
    assert not output.exists()


def test_unreadable_manifest_raises_error(tmp_path: Path):
    with pytest.raises(ManifestError, match="cannot read manifest"):
        scan_manifest(tmp_path / "missing.yaml")


def test_invalid_encoding_fails_scan(tmp_path: Path):
    (tmp_path / "horustrace.manifest.yaml").write_bytes(b"\xff")
    with pytest.raises(ManifestError, match="not valid UTF-8"):
        scan(tmp_path)


def test_empty_mapping_manifest_remains_valid(tmp_path: Path):
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text("{}", encoding="utf-8")
    graph, findings = scan(tmp_path)
    assert graph.agents == []
    assert findings == []
