from pathlib import Path

from horustrace.scanner import scan


def test_langgraph_nodes_and_control_edges_project_to_adg(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph, END


def fetch(state):
    return state


def execute(state):
    return state

workflow = StateGraph(dict)
workflow.add_node("fetch", fetch)
workflow.add_node("execute", execute)
workflow.add_edge("fetch", "execute")
workflow.add_edge("execute", END)
app = workflow.compile()
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    assert {tool.name for tool in agent.tools} == {"fetch", "execute"}
    assert ("fetch", "execute") in agent.metadata["control_edges"]
    assert graph.adg is not None
    assert any(edge.kind == "CONTROL_FLOWS_TO" for edge in graph.adg.edges)


def test_langgraph_re_compile_is_not_process_execution(tmp_path: Path) -> None:
    write(
        tmp_path,
        "agent.py",
        """import re
from langgraph.graph import StateGraph

def validate_email(state):
    pattern = re.compile(r"^[^@]+@[^@]+$")
    return {"valid": bool(pattern.match(state["email"]))}

workflow = StateGraph(dict)
workflow.add_node("validate_email", validate_email)
""",
    )
    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "validate_email")
    assert "process.execute" not in tool.capabilities
    assert not any(f.rule_id == "AGT020" for f in findings)
