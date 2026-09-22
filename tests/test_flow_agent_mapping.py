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
