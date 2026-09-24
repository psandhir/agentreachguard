from pathlib import Path

from horustrace.models import AgentReachability, FlowExecutionContext
from horustrace.scanner import scan


def _write_observer_agent(root: Path) -> None:
    (root / "agent.py").write_text(
        """
from agents import Agent

def safe_tool():
    return "ok"

agent = Agent(name="Observer", tools=[safe_tool])
""",
        encoding="utf-8",
    )


def _write_dangerous_flow(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
def dangerous_helper():
    value = input("command: ")
    return eval(value)
""",
        encoding="utf-8",
    )


def test_mapped_agent_tool_flow_is_proven_reachable(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
import requests

def forward_external_result():
    response = requests.get("https://source.example/data")
    return requests.post(
        "https://sink.example/events",
        json=response.json(),
    )
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from tools import forward_external_result

agent = Agent(name="Orchestrator", tools=[forward_external_result])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "external_http_response"
        and item.sink_kind == "external_send"
    )

    assert flow.execution_context is FlowExecutionContext.AGENT_TOOL
    assert (
        flow.agent_reachability
        is AgentReachability.PROVEN_AGENT_REACHABLE
    )
    assert flow.as_dict()["execution_context"] == "agent_tool"
    assert (
        flow.as_dict()["agent_reachability"]
        == "proven_agent_reachable"
    )


def test_unmapped_test_flow_is_proven_non_agent(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    _write_dangerous_flow(tmp_path / "tests" / "test_helper.py")

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
    )

    assert flow.agent is None
    assert flow.execution_context is FlowExecutionContext.TEST
    assert flow.agent_reachability is AgentReachability.PROVEN_NON_AGENT
    assert (
        flow.metadata["agent_reachability_basis"]
        == "non_agent_execution_context_without_tool_binding"
    )


def test_unmapped_cli_flow_is_proven_non_agent(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    _write_dangerous_flow(tmp_path / "cli.py")

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
    )

    assert flow.execution_context is FlowExecutionContext.CLI
    assert flow.agent_reachability is AgentReachability.PROVEN_NON_AGENT


def test_main_guard_flow_is_proven_non_agent_cli(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    (tmp_path / "register.py").write_text(
        """
def register_oauth():
    value = input("command: ")
    return eval(value)

if __name__ == "__main__":
    register_oauth()
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
    )

    assert flow.execution_context is FlowExecutionContext.CLI
    assert flow.agent_reachability is AgentReachability.PROVEN_NON_AGENT
    assert flow.metadata["execution_context_basis"] == "python_main_guard"


def test_project_script_export_flow_is_proven_non_agent_cli(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    package = tmp_path / "libs" / "code" / "deepagents_code"
    package.mkdir(parents=True)
    (package / "main.py").write_text(
        """
def cli_main():
    value = input("command: ")
    return eval(value)
""",
        encoding="utf-8",
    )
    (tmp_path / "libs" / "code" / "pyproject.toml").write_text(
        """
[project]
name = "deepagents-code"
version = "0.1.0"

[project.scripts]
deepagents-code = "deepagents_code:cli_main"
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
    )

    assert flow.execution_context is FlowExecutionContext.CLI
    assert flow.agent_reachability is AgentReachability.PROVEN_NON_AGENT
    assert flow.metadata["execution_context_basis"] == "project_script_entrypoint"


def test_unmapped_runtime_flow_remains_unknown(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    _write_dangerous_flow(tmp_path / "worker.py")

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.source_kind == "user_input"
    )

    assert flow.execution_context is FlowExecutionContext.RUNTIME
    assert flow.agent_reachability is AgentReachability.UNKNOWN
    assert (
        flow.metadata["agent_reachability_basis"]
        == "no_agent_tool_binding_evidence"
    )


def test_flow_coverage_reports_context_and_reachability(tmp_path: Path) -> None:
    _write_observer_agent(tmp_path)
    _write_dangerous_flow(tmp_path / "tests" / "test_helper.py")
    _write_dangerous_flow(tmp_path / "worker.py")

    graph, _ = scan(tmp_path)
    flows = graph.coverage.resolution["flows"]

    assert flows["supported_paths"] == 2
    assert flows["agent_mapped"] == 0
    assert flows["agent_attribution_gaps"] == 0
    assert flows["execution_contexts"]["test"] == 1
    assert flows["execution_contexts"]["runtime"] == 1
    assert flows["agent_reachability"]["proven_non_agent"] == 1
    assert flows["agent_reachability"]["unknown"] == 1


def test_non_agent_context_is_proven_without_any_normalized_agents(tmp_path: Path) -> None:
    _write_dangerous_flow(tmp_path / "scripts" / "maintenance.py")
    _write_dangerous_flow(tmp_path / "tests" / "test_helper.py")

    graph, _ = scan(tmp_path)

    by_context = {flow.execution_context: flow for flow in graph.flow_paths}
    assert by_context[FlowExecutionContext.APPLICATION_SUPPORT].agent_reachability is (
        AgentReachability.PROVEN_NON_AGENT
    )
    assert by_context[FlowExecutionContext.TEST].agent_reachability is (
        AgentReachability.PROVEN_NON_AGENT
    )
    assert not graph.agents


def test_runtime_flow_without_normalized_agents_remains_unknown(tmp_path: Path) -> None:
    _write_dangerous_flow(tmp_path / "worker.py")

    graph, _ = scan(tmp_path)
    flow = next(iter(graph.flow_paths))

    assert not graph.agents
    assert flow.execution_context is FlowExecutionContext.RUNTIME
    assert flow.agent_reachability is AgentReachability.UNKNOWN
