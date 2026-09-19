from pathlib import Path

import pytest

from agentreachguard.scanner import ScannerError, scan


def test_external_file_symlink_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-agent.py"
    outside.write_text("this is deliberately invalid Python(", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "escaped.py").symlink_to(outside)

    graph, _ = scan(project)

    assert graph.coverage.files_skipped == 1
    assert not any(diagnostic.code == "parse_error" for diagnostic in graph.coverage.diagnostics)
    assert any("outside the scan root" in diagnostic.message for diagnostic in graph.coverage.diagnostics)


def test_internal_file_symlink_remains_scannable(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "agent.py"
    source.write_text("from agents import Agent, ShellTool\nagent = Agent(name='ops', tools=[ShellTool()])\n")
    (project / "linked.py").symlink_to(source)

    _, findings = scan(project)

    assert any(finding.rule_id == "AGT020" for finding in findings)


def test_external_explicit_suppression_file_is_rejected(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("version: 1\nsuppressions: []\n")

    with pytest.raises(ScannerError, match="outside the scan root"):
        scan(project, suppressions_path=outside)
