from pathlib import Path

from horustrace.flow import analyze_repository_flows
from horustrace.models import Agent, Graph, SourceLocation, Tool


def _write_flow_source(tmp_path: Path) -> Path:
    path = tmp_path / "tools.py"
    path.write_text(
        """
def dangerous_tool():
    value = input("command: ")
    return eval(value)
""",
        encoding="utf-8",
    )
    return path


def test_cross_file_unique_tool_binding_maps_flow_to_agent(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text("# normalized agent declaration lives here\n", encoding="utf-8")

    graph = Graph(
        agents=[
            Agent(
                name="executor",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
            Agent(
                name="observer",
                tools=[
                    Tool(
                        name="read_status",
                        kind="function",
                        location=SourceLocation(declaration, 2, 1),
                    )
                ],
            ),
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent == "executor"
    assert flows[0].source_kind == "user_input"
    assert flows[0].sink_kind == "process_execute"


def test_cross_file_ambiguous_tool_binding_remains_unmapped(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text("# two agents expose the same imported tool\n", encoding="utf-8")

    graph = Graph(
        agents=[
            Agent(
                name="executor_a",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
            Agent(
                name="executor_b",
                tools=[
                    Tool(
                        name="dangerous_tool",
                        kind="function",
                        location=SourceLocation(declaration, 2, 1),
                    )
                ],
            ),
        ]
    )

    flows = analyze_repository_flows(tmp_path, [source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent is None



def test_frozen_corpus_style_openai_imported_tool_maps_flow(tmp_path: Path) -> None:
    """Mirrors the imported-tool/source->external-send shape seen in Cohort C."""
    tools_path = tmp_path / "tools.py"
    tools_path.write_text(
        """
import requests

def forward_external_result():
    response = requests.get("https://source.example/data")
    return requests.post("https://sink.example/events", json=response.json())
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

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "external_http_response"
        and flow.sink_kind == "external_send"
    ]

    assert flows
    assert {flow.agent for flow in flows} == {"Orchestrator"}
    tool = next(t for t in graph.agents[0].tools if t.name == "forward_external_result")
    assert tool.metadata["source_function_key"] == "tools.forward_external_result"


def test_frozen_corpus_style_langgraph_node_maps_flow(tmp_path: Path) -> None:
    """Mirrors Cohort C LangGraph source->process execution flow shapes."""
    (tmp_path / "workflow.py").write_text(
        """
import requests
import subprocess
from langgraph.graph import StateGraph

def fetch_and_execute(state):
    response = requests.get("https://source.example/task")
    subprocess.run(response.text, shell=True)

workflow = StateGraph(dict)
workflow.add_node("executor", fetch_and_execute)
""",
        encoding="utf-8",
    )

    from horustrace.scanner import scan

    graph, _ = scan(tmp_path)
    flows = [
        flow
        for flow in graph.flow_paths
        if flow.source_kind == "external_http_response"
        and flow.sink_kind == "process_execute"
    ]

    assert len(flows) == 1
    assert flows[0].agent == "workflow"
    tool = next(t for t in graph.agents[0].tools if t.name == "executor")
    assert tool.metadata["source_function_key"] == "workflow.fetch_and_execute"
