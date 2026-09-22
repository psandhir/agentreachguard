from pathlib import Path

from horustrace.bindings import enrich_python_tool_bindings
from horustrace.flow import analyze_repository_flows
from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.scanner import scan


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


def test_cross_file_binding_uses_function_provenance(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text(
        "from tools import dangerous_tool\n",
        encoding="utf-8",
    )

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
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
        ]
    )

    enrich_python_tool_bindings(graph, tmp_path, [declaration, source_path])
    flows = analyze_repository_flows(tmp_path, [declaration, source_path], graph)

    tool = graph.agents[0].tools[0]
    assert tool.metadata["function_qualified_name"] == "tools.dangerous_tool"
    assert flows[0].agent == "executor"
    assert flows[0].metadata["agent_binding"]["basis"] == "tool_function_provenance"
    assert flows[0].source_kind == "user_input"
    assert flows[0].sink_kind == "process_execute"


def test_cross_file_ambiguous_provenance_remains_unmapped(tmp_path: Path) -> None:
    source_path = _write_flow_source(tmp_path)
    declaration = tmp_path / "agent.py"
    declaration.write_text(
        "from tools import dangerous_tool\n",
        encoding="utf-8",
    )

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
                        location=SourceLocation(declaration, 1, 1),
                    )
                ],
            ),
        ]
    )

    enrich_python_tool_bindings(graph, tmp_path, [declaration, source_path])
    flows = analyze_repository_flows(tmp_path, [declaration, source_path], graph)

    assert len(flows) == 1
    assert flows[0].agent is None
    assert flows[0].metadata["agent_binding"]["basis"] == (
        "ambiguous_tool_function_provenance"
    )


def test_imported_openai_tool_flow_maps_end_to_end(tmp_path: Path) -> None:
    """Regression for the imported-tool shape seen throughout the frozen corpus."""
    (tmp_path / "tools.py").write_text(
        """
from agents import function_tool

@function_tool
def forward_external_content():
    import requests
    payload = requests.get("https://example.invalid/input").text
    return requests.post("https://example.invalid/output", data=payload)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from tools import forward_external_content

agent = Agent(name="Researcher", tools=[forward_external_content])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert len(graph.flow_paths) == 1
    flow = graph.flow_paths[0]
    assert flow.agent == "Researcher"
    assert flow.source_kind == "external_http_response"
    assert flow.sink_kind == "external_send"
    assert flow.metadata["agent_binding"]["function"] == (
        "tools.forward_external_content"
    )
    tool = graph.agents[0].tools[0]
    assert tool.metadata["function_qualified_name"] == (
        "tools.forward_external_content"
    )
    assert any(
        fact.fact == "python_function=tools.forward_external_content"
        for fact in tool.provenance
    )
