import json
from pathlib import Path

import pytest

from horustrace.cli import main
from horustrace.coverage import add_diagnostic
from horustrace.limits import ScanLimitError
from horustrace.models import ScanCoverage, ScanDiagnostic
from horustrace.scanner import scan


@pytest.mark.parametrize(("source", "kind", "diagnostic_id"), [
    ("root_agent = Agent(name='ops', **config)", "dynamic_configuration", "ARG-COV-004"),
    ("root_agent = Agent(name='ops', tools=build_tools())", "dynamic_configuration", "ARG-COV-004"),
    ("root_agent = Agent(name='ops', tools=[GoogleApiToolset(tool_filter=build_filter())])", "dynamic_tool_filter", "ARG-COV-006"),
    ("params = SseConnectionParams(url=build_url())\nroot_agent = Agent(name='ops', tools=[McpToolset(connection_params=params)])", "dynamic_mcp_endpoint", "ARG-COV-005"),
])
def test_dynamic_security_constructs_have_stable_diagnostics(
    tmp_path: Path, source: str, kind: str, diagnostic_id: str
) -> None:
    (tmp_path / "agent.py").write_text(
        "from google.adk import Agent\n"
        "from google.adk.tools import GoogleApiToolset, McpToolset\n"
        "from google.adk.tools.mcp_tool.mcp_toolset import SseConnectionParams\n"
        "config = {}\n"
        "def build_tools(): return []\n"
        "def build_filter(): return []\n"
        "def build_url(): return 'https://example.test'\n"
        f"{source}\n",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    diagnostic = next(item for item in graph.coverage.diagnostics if item.kind == kind)
    assert diagnostic.diagnostic_id == diagnostic_id
    assert diagnostic.incomplete


def test_json_and_sarif_keep_machine_diagnostic_identifiers(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text("from google.adk import Agent\nroot_agent = Agent(name='ops', **config)\n")
    assert main(["scan", str(tmp_path), "--strict", "--format", "json", "--fail-on", "none"]) == 1
    report = json.loads(capsys.readouterr().out)
    diagnostic = report["coverage"]["diagnostics"][0]
    assert diagnostic["diagnostic_id"] == "ARG-COV-004"
    assert diagnostic["kind"] == "dynamic_configuration"

    assert main(["scan", str(tmp_path), "--strict", "--format", "sarif", "--fail-on", "none"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    notification = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["properties"]["diagnostic_id"] == "ARG-COV-004"


def test_external_helper_semantics_are_explicitly_incomplete(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from google.adk import Agent\n"
        "from external_tools import build_tools\n"
        "root_agent = Agent(name='ops', tools=[build_tools])\n",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    diagnostic = next(
        item for item in graph.coverage.diagnostics
        if item.kind == "external_helper_semantics_unresolved"
    )
    assert diagnostic.diagnostic_id == "ARG-COV-008"
    assert diagnostic.incomplete


def test_coverage_diagnostic_ceiling_is_enforced() -> None:
    coverage = ScanCoverage()
    for index in range(1000):
        add_diagnostic(coverage, ScanDiagnostic("dynamic_configuration", str(index)))
    with pytest.raises(ScanLimitError):
        add_diagnostic(coverage, ScanDiagnostic("dynamic_configuration", "overflow"))
