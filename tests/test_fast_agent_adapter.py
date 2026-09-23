from pathlib import Path

from horustrace.models import AgentReachability
from horustrace.scanner import scan


def test_fast_agent_decorator_normalizes_agent_and_explicit_tools(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from fast_agent import FastAgent

fast = FastAgent("Ops App")

def run_user_command():
    value = input("command: ")
    subprocess.run(value, shell=True)

@fast.agent(
    name="ops",
    function_tools=[run_user_command],
    servers=["filesystem"],
    shell=True,
    human_input=True,
    model="sonnet",
)
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ops")

    assert agent.metadata["framework"] == "fast-agent"
    assert agent.metadata["agent_type"] == "agent"
    assert agent.metadata["app_name"] == "Ops App"
    assert agent.metadata["mcp_server_refs"] == ["filesystem"]
    assert agent.metadata["model"] == "sonnet"
    assert {tool.name for tool in agent.tools} == {"run_user_command", "shell"}
    assert "process.execute" in next(
        tool for tool in agent.tools if tool.name == "run_user_command"
    ).capabilities
    assert agent.inputs[0].name == "human_input"

    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
        and item.sink_kind == "process_execute"
    )
    assert flow.agent == "ops"
    assert flow.agent_reachability is AgentReachability.PROVEN_AGENT_REACHABLE


def test_fast_agent_workflows_project_delegation_edges(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Workflow")

@fast.agent(name="researcher")
@fast.agent(name="writer")
@fast.agent(name="grader")
@fast.parallel(
    name="parallel",
    fan_out=["researcher", "writer"],
    fan_in="grader",
)
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    parallel = next(item for item in graph.agents if item.name == "parallel")

    assert parallel.metadata["agent_type"] == "parallel"
    assert parallel.metadata["delegates_to"] == [
        "researcher",
        "writer",
        "grader",
    ]
    assert graph.adg is not None
    assert sum(edge.kind == "DELEGATES_TO" for edge in graph.adg.edges) == 3


def test_fast_agent_scoped_tool_binds_to_unique_agent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from fast_agent import FastAgent

fast = FastAgent("Scoped")

@fast.agent(name="researcher")
async def researcher():
    pass

@researcher.tool(name="fetch_external")
def fetch_url():
    return requests.get("https://example.test/data")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "researcher")
    tool = next(item for item in agent.tools if item.name == "fetch_external")

    assert tool.metadata["framework"] == "fast-agent"
    assert tool.metadata["source"] == "scoped_tool_decorator"
    assert "network.external" in tool.capabilities


def test_fast_agent_global_tool_remains_unbound_without_explicit_scope(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Global")

@fast.tool
def lookup_record():
    return "ok"

@fast.agent(name="worker")
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert [agent.name for agent in graph.agents] == ["worker"]
    assert [tool.name for tool in graph.unbound_tools] == ["lookup_record"]
    assert graph.unbound_tools[0].metadata["source"] == "global_tool_decorator"
    assert any(
        diagnostic.kind == "unresolved_tool"
        and diagnostic.details.get("construct") == "global_tool"
        for diagnostic in graph.coverage.diagnostics
    )


def test_fast_agent_router_normalizes_agent_targets_and_mcp_filters(
    tmp_path: Path,
) -> None:
    (tmp_path / "router.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Router")

@fast.agent(name="code")
@fast.agent(name="general")
@fast.router(
    name="route",
    agents=["code", "general"],
    servers=["filesystem"],
    tools={"filesystem": ["read_file"]},
)
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    router = next(item for item in graph.agents if item.name == "route")

    assert router.metadata["delegates_to"] == ["code", "general"]
    assert router.metadata["mcp_server_refs"] == ["filesystem"]
    assert router.metadata["mcp_tool_filters"] == {
        "filesystem": ["read_file"],
    }
    assert any(
        diagnostic.kind == "unsupported_security_construct"
        and diagnostic.details.get("construct") == "mcp_server_reference"
        for diagnostic in graph.coverage.diagnostics
    )


def test_fast_agent_import_without_application_is_not_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "config_only.py").write_text(
        "from fast_agent import config\n",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    assert graph.agents == []
    assert findings == []


def test_fast_agent_dynamic_server_refs_are_explicitly_incomplete(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Dynamic")
servers = load_server_names()

@fast.agent(name="worker", servers=servers)
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert any(
        diagnostic.kind == "dynamic_configuration"
        and diagnostic.details.get("construct") == "mcp_server_reference"
        for diagnostic in graph.coverage.diagnostics
    )
