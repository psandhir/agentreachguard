import json
from pathlib import Path

import pytest

from agentreachguard.cli import main
from agentreachguard.scanner import scan


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
